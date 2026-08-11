<?php
header('Content-Type: application/json; charset=utf-8');

$rawInput = file_get_contents('php://input');
$inputData = json_decode($rawInput, true) ?: [];

$action = $_GET['action'] ?? ($inputData['action'] ?? ($_POST['action'] ?? ''));

$ipFile     = '/etc/nginx/rules/ip_blacklist.conf';
$uaFile     = '/etc/nginx/rules/ua_blacklist.conf';
$tokenFile  = '/etc/nginx/rules/token_blacklist.conf';
$reloadFlag = '/etc/nginx/rules/.reload_flag';

function getNginxConfPath() {
    $confFiles = glob('/etc/nginx/conf.d/*.conf');
    return !empty($confFiles) ? $confFiles[0] : '/etc/nginx/conf.d/default.conf';
}

$logFile = '/var/log/nginx/access.log';

function safeWriteFile($filePath, $content, $append = false) {
    $dir = dirname($filePath);
    if (!is_dir($dir)) {
        @mkdir($dir, 0777, true);
        @chmod($dir, 0777);
    }
    if (file_exists($filePath)) {
        @chmod($filePath, 0666);
    }
    $flags = $append ? FILE_APPEND : 0;
    $result = @file_put_contents($filePath, $content, $flags);
    if ($result !== false) {
        @chmod($filePath, 0666);
        return true;
    }
    return false;
}

function formatRule($type, $value) {
    switch ($type) {
        case 'ip': return "deny {$value};";
        case 'ua': 
            $safeVal = preg_quote($value, '/');
            return "if (\$http_user_agent ~* \"{$safeVal}\") { return 403; }";
        case 'token': return "if (\$arg_token = \"{$value}\") { return 403; }";
        default: return '';
    }
}

function parseRuleValue($type, $line) {
    $line = trim($line);
    if (empty($line) || str_starts_with($line, '#')) return null;

    if ($type === 'ip' && preg_match('/^deny\s+([^;]+);/', $line, $m)) return $m[1];
    if ($type === 'ua' && preg_match('/if\s+\(\$http_user_agent\s+~*\s+"([^"]+)"\)/', $line, $m)) return stripcslashes($m[1]);
    if ($type === 'token' && preg_match('/if\s+\(\$arg_token\s+=\s+"([^"]+)"\)/', $line, $m)) return $m[1];
    return null;
}

function getSslCertificateInfo() {
    $certPath = '/etc/nginx/ssl/cert.pem';
    if (file_exists($certPath) && is_readable($certPath)) {
        $certContent = @file_get_contents($certPath);
        if ($certContent) {
            $certData = @openssl_x509_parse($certContent);
            if ($certData) {
                $validTo = $certData['validTo_time_t'] ?? 0;
                $daysLeft = ceil(($validTo - time()) / 86400);
                $domain = $certData['subject']['CN'] ?? '';
                if (isset($certData['extensions']['subjectAltName'])) {
                    $sans = explode(',', $certData['extensions']['subjectAltName']);
                    $cleanedSans = array_map(fn($s) => trim(str_replace('DNS:', '', $s)), $sans);
                    if (!empty($cleanedSans)) $domain = implode(', ', $cleanedSans);
                }
                $issuer = $certData['issuer']['O'] ?? ($certData['issuer']['CN'] ?? 'Let\'s Encrypt');
                return ['status' => 'success', 'cert' => ['domain' => $domain ?: '未知域名', 'issuer' => $issuer, 'valid_to' => date('Y-m-d H:i:s', $validTo), 'days_left' => max(0, (int)$daysLeft)]];
            }
        }
    }
    return ['status' => 'error', 'message' => '未检测到有效 SSL 证书文件'];
}

// 1. 获取日志
if ($action === 'logs' || $action === 'get_logs') {
    $logs = [];
    if (file_exists($logFile)) {
        $cmd = "tail -n 300 " . escapeshellarg($logFile);
        exec($cmd, $lines);
        $lines = array_reverse($lines);
        $pattern = '/^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+)\s+([^\s"]*)[^"]*" (\d+) \d+ "([^"]*)" "([^"]*)"/';

        foreach ($lines as $line) {
            if (preg_match($pattern, $line, $m)) {
                $rawIp = $m[1]; $time = $m[2]; $method = $m[3]; $url = $m[4]; $status = $m[5];
                $referer = ($m[6] === '-') ? '' : $m[6];
                $ua = ($m[7] === '-') ? '' : $m[7];
                $token = '';
                $parsedUrl = parse_url($url);
                if (isset($parsedUrl['query'])) {
                    parse_str($parsedUrl['query'], $queryParams);
                    $token = $queryParams['token'] ?? '';
                }
                $logs[] = ['ip' => $rawIp, 'time' => $time, 'method' => $method, 'path' => $parsedUrl['path'] ?? $url, 'url' => $url, 'status' => (int)$status, 'token' => $token, 'ua' => $ua, 'referer' => $referer];
            }
        }
    }
    echo json_encode(['status' => 'success', 'data' => $logs]);
    exit;
}

// 2. 规则列表
if ($action === 'list') {
    $getRules = function($filePath, $type) {
        if (!file_exists($filePath)) return [];
        $lines = file($filePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $rules = [];
        foreach ($lines as $line) {
            $val = parseRuleValue($type, $line);
            if ($val !== null) $rules[] = $val;
        }
        return array_values(array_unique($rules));
    };
    echo json_encode(['status' => 'success', 'data' => ['ip' => $getRules($ipFile, 'ip'), 'ua' => $getRules($uaFile, 'ua'), 'token' => $getRules($tokenFile, 'token')]]);
    exit;
}

// 3. 封禁
if ($action === 'ban') {
    $type = $inputData['type'] ?? ($_POST['type'] ?? '');
    $value = trim($inputData['value'] ?? ($_POST['value'] ?? ''));
    $targetFile = match($type) { 'ip' => $ipFile, 'ua' => $uaFile, 'token' => $tokenFile, default => '' };
    if (empty($targetFile) || empty($value)) { echo json_encode(['status' => 'error', 'message' => '参数不合法']); exit; }
    $ruleLine = formatRule($type, $value);
    $existing = file_exists($targetFile) ? file_get_contents($targetFile) : '';
    if (!str_contains($existing, $ruleLine)) {
        safeWriteFile($targetFile, $ruleLine . "\n", true);
        safeWriteFile($reloadFlag, time());
    }
    echo json_encode(['status' => 'success', 'message' => '封禁成功']);
    exit;
}

// 4. 解封
if ($action === 'unban') {
    $type = $inputData['type'] ?? ($_POST['type'] ?? '');
    $value = trim($inputData['value'] ?? ($_POST['value'] ?? ''));
    $targetFile = match($type) { 'ip' => $ipFile, 'ua' => $uaFile, 'token' => $tokenFile, default => '' };
    if ($targetFile && file_exists($targetFile)) {
        $lines = file($targetFile, FILE_IGNORE_NEW_LINES);
        $newLines = array_filter($lines, fn($line) => parseRuleValue($type, $line) !== $value);
        safeWriteFile($targetFile, implode("\n", $newLines) . "\n");
        safeWriteFile($reloadFlag, time());
    }
    echo json_encode(['status' => 'success', 'message' => '解封成功']);
    exit;
}

// 5. 证书状态
if ($action === 'cert_status') { echo json_encode(getSslCertificateInfo()); exit; }

// 6. 获取域名
if ($action === 'get_domain') {
    $confPath = getNginxConfPath();
    $domain = '';
    if (file_exists($confPath) && preg_match('/\bserver_name\s+([^;]+);/', file_get_contents($confPath), $m)) {
        $domain = trim($m[1]);
    }
    echo json_encode(['domain' => $domain, 'cert_status' => getSslCertificateInfo()]);
    exit;
}

// 7. 更新域名
if ($action === 'update_domain' || $action === 'apply_cert') {
    $newDomain = trim($inputData['domain'] ?? ($_POST['domain'] ?? ''));
    $confPath = getNginxConfPath();
    if (file_exists($confPath)) {
        $conf = file_get_contents($confPath);
        safeWriteFile($confPath, preg_replace('/\bserver_name\s+[^;]+;/', "server_name {$newDomain};", $conf));
    }
    safeWriteFile('/etc/nginx/rules/.cert_flag', $newDomain);
    echo json_encode(['status' => 'success', 'message' => '配置已更新']);
    exit;
}

// 8. 获取反代目标
if ($action === 'get_upstream') {
    $confPath = getNginxConfPath();
    $targetDomain = '';
    if (file_exists($confPath)) {
        $conf = file_get_contents($confPath);
        if (preg_match('/location\s+@proxy\s*\{[^}]*proxy_ssl_name\s+([^;]+);/s', $conf, $matches)) {
            $targetDomain = trim($matches[1]);
        } elseif (preg_match('/location\s+@proxy\s*\{[^}]*proxy_pass\s+https?:\/\/([^\/;\s]+)/s', $conf, $matches)) {
            $targetDomain = trim($matches[1]);
        }
    }
    echo json_encode(['status' => 'success', 'upstream' => $targetDomain]);
    exit;
}

// 9. 修改反代目标（精准匹配 location @proxy）
if ($action === 'update_upstream') {
    $newTarget = trim($inputData['target_domain'] ?? ($_POST['target_domain'] ?? ''));
    if (empty($newTarget)) {
        echo json_encode(['status' => 'error', 'message' => '机场域名不能为空']);
        exit;
    }
    $newTarget = preg_replace('/^https?:\/\//i', '', $newTarget);
    $newTarget = rtrim($newTarget, '/');

    $confPath = getNginxConfPath();
    if (!file_exists($confPath)) {
        echo json_encode(['status' => 'error', 'message' => "找不到配置文件"]);
        exit;
    }

    $conf = file_get_contents($confPath);

    // 鲁棒性极强的正则匹配 location @proxy 块
    if (preg_match('/(location\s+@proxy\s*\{)([\s\S]*?)(\n\s*\})/i', $conf, $matches)) {
        $subBlock = $matches[2];

        $subBlock = preg_replace('/proxy_pass\s+[^;]+;/', "proxy_pass https://{$newTarget};", $subBlock);
        if (!str_contains($subBlock, 'proxy_pass')) $subBlock .= "\n        proxy_pass https://{$newTarget};";

        $subBlock = preg_replace('/proxy_set_header\s+Host\s+[^;]+;/', "proxy_set_header Host {$newTarget};", $subBlock);
        if (!str_contains($subBlock, 'proxy_set_header Host')) $subBlock .= "\n        proxy_set_header Host {$newTarget};";

        $subBlock = preg_replace('/proxy_ssl_name\s+[^;]+;/', "proxy_ssl_name {$newTarget};", $subBlock);
        if (!str_contains($subBlock, 'proxy_ssl_name')) $subBlock .= "\n        proxy_ssl_name {$newTarget};";

        if (!str_contains($subBlock, 'proxy_ssl_server_name on;')) $subBlock .= "\n        proxy_ssl_server_name on;";

        $newConf = str_replace($matches[0], $matches[1] . $subBlock . $matches[3], $conf);

        if (!safeWriteFile($confPath, $newConf)) {
            echo json_encode(['status' => 'error', 'message' => "写入失败，请检查文件权限"]);
            exit;
        }

        safeWriteFile($reloadFlag, time());
        echo json_encode(['status' => 'success', 'message' => "已成功将反代目标替换为: {$newTarget}"]);
        exit;
    } else {
        echo json_encode(['status' => 'error', 'message' => '未找到 @proxy 配置块']);
        exit;
    }
}

echo json_encode(['status' => 'error', 'message' => '无效操作']);
