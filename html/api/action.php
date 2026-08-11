<?php
header('Content-Type: application/json; charset=utf-8');

// 统一解析来自前端的 JSON Body、GET 与 POST 参数
$rawInput = file_get_contents('php://input');
$inputData = json_decode($rawInput, true) ?: [];

$action = $_GET['action'] ?? ($inputData['action'] ?? ($_POST['action'] ?? ''));

$ipFile     = '/etc/nginx/rules/ip_blacklist.conf';
$uaFile     = '/etc/nginx/rules/ua_blacklist.conf';
$tokenFile  = '/etc/nginx/rules/token_blacklist.conf';
$reloadFlag = '/etc/nginx/rules/.reload_flag';

// 智能日志路径判断（优先匹配订阅代理日志 sub_access.log，若无则使用默认 access.log）
$logFile = file_exists('/var/log/nginx/sub_access.log') 
    ? '/var/log/nginx/sub_access.log' 
    : '/var/log/nginx/access.log';

// ------------------- 辅助函数 -------------------

function formatRule($type, $value) {
    switch ($type) {
        case 'ip':
            return "deny {$value};";
        case 'ua':
            $safeVal = preg_quote($value, '/');
            return "if (\$http_user_agent ~* \"{$safeVal}\") { return 403; }";
        case 'token':
            return "if (\$arg_token = \"{$value}\") { return 403; }";
        default:
            return '';
    }
}

function parseRuleValue($type, $line) {
    $line = trim($line);
    if (empty($line) || str_starts_with($line, '#')) return null;

    if ($type === 'ip' && preg_match('/^deny\s+([^;]+);/', $line, $m)) {
        return $m[1];
    }
    if ($type === 'ua' && preg_match('/if\s+\(\$http_user_agent\s+~*\s+"([^"]+)"\)/', $line, $m)) {
        return stripcslashes($m[1]);
    }
    if ($type === 'token' && preg_match('/if\s+\(\$arg_token\s+=\s+"([^"]+)"\)/', $line, $m)) {
        return $m[1];
    }
    return null;
}

/**
 * 解析并获取当前 SSL 证书详细状态（宝塔面板风格数据源）
 */
function getSslCertificateInfo() {
    $certPath = '/etc/nginx/ssl/cert.pem';
    
    // 1. 优先尝试直接解析挂载的本地证书文件
    if (file_exists($certPath) && is_readable($certPath)) {
        $certContent = @file_get_contents($certPath);
        if ($certContent) {
            $certData = @openssl_x509_parse($certContent);
            if ($certData) {
                $validTo = $certData['validTo_time_t'] ?? 0;
                $daysLeft = ceil(($validTo - time()) / 86400);
                
                // 提取域名 (优先提取主题扩展 SAN 或 通用名 CN)
                $domain = $certData['subject']['CN'] ?? '';
                if (isset($certData['extensions']['subjectAltName'])) {
                    $sans = explode(',', $certData['extensions']['subjectAltName']);
                    $cleanedSans = array_map(function($s) {
                        return trim(str_replace('DNS:', '', $s));
                    }, $sans);
                    if (!empty($cleanedSans)) {
                        $domain = implode(', ', $cleanedSans);
                    }
                }

                // 提取签发机构名称
                $issuer = $certData['issuer']['O'] ?? ($certData['issuer']['CN'] ?? 'Let\'s Encrypt');

                return [
                    'status' => 'success',
                    'cert' => [
                        'domain'    => $domain ?: '未知域名',
                        'issuer'    => $issuer,
                        'valid_to'  => date('Y-m-d H:i:s', $validTo),
                        'days_left' => max(0, (int)$daysLeft)
                    ]
                ];
            }
        }
    }

    // 2. 若文件不可读取，尝试发起 443 SSL 握手实时探测
    $host = $_SERVER['HTTP_HOST'] ?? '';
    $domain = explode(':', $host)[0];
    if (!empty($domain) && $domain !== 'localhost' && !filter_var($domain, FILTER_VALIDATE_IP)) {
        $context = stream_context_create([
            "ssl" => [
                "capture_peer_cert" => true,
                "verify_peer"       => false,
                "verify_peer_name"  => false
            ]
        ]);
        $client = @stream_socket_client("ssl://{$domain}:443", $errno, $errstr, 3, STREAM_CLIENT_CONNECT, $context);
        if ($client) {
            $params = stream_context_get_params($client);
            fclose($client);
            if (isset($params["options"]["ssl"]["peer_certificate"])) {
                $certData = openssl_x509_parse($params["options"]["ssl"]["peer_certificate"]);
                $validTo  = $certData['validTo_time_t'] ?? 0;
                $daysLeft = ceil(($validTo - time()) / 86400);
                $issuer   = $certData['issuer']['O'] ?? ($certData['issuer']['CN'] ?? 'Let\'s Encrypt');

                return [
                    'status' => 'success',
                    'cert' => [
                        'domain'    => $certData['subject']['CN'] ?? $domain,
                        'issuer'    => $issuer,
                        'valid_to'  => date('Y-m-d H:i:s', $validTo),
                        'days_left' => max(0, (int)$daysLeft)
                    ]
                ];
            }
        }
    }

    // 3. 检查是否有后台申请中的任务状态
    $statusFile = '/etc/nginx/rules/cert_status.json';
    if (file_exists($statusFile)) {
        $json = json_decode(file_get_contents($statusFile), true);
        if (!empty($json)) {
            return [
                'status'  => 'processing',
                'message' => $json['msg'] ?? '证书申请中...'
            ];
        }
    }

    return [
        'status'  => 'error',
        'message' => '未检测到有效 SSL 证书文件或 443 端口未启用 SSL'
    ];
}

// ------------------- 路由处理 -------------------

// 1. 获取最新日志（仅取末尾 300 行，解决慢和 UA 缺失问题）
if ($action === 'logs' || $action === 'get_logs') {
    $logs = [];
    if (file_exists($logFile)) {
        // 使用 tail 指令秒级读取末尾最新日志
        $cmd = "tail -n 300 " . escapeshellarg($logFile);
        exec($cmd, $lines);
        $lines = array_reverse($lines);

        // 匹配 Nginx 默认 combined 格式: 
        // IP - - [时间] "请求方法 路径 协议" 状态码 发送字节数 "Referer" "User-Agent"
        $pattern = '/^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+)\s+([^\s"]*)[^"]*" (\d+) \d+ "([^"]*)" "([^"]*)"/';

        foreach ($lines as $line) {
            if (preg_match($pattern, $line, $m)) {
                $rawIp   = $m[1];
                $time    = $m[2];
                $method  = $m[3];
                $url     = $m[4];
                $status  = $m[5];
                $referer = ($m[6] === '-') ? '' : $m[6];
                $ua      = ($m[7] === '-') ? '' : $m[7]; // 正确提取 UA

                // 提取 URL 参数中的 token
                $token = '';
                $parsedUrl = parse_url($url);
                if (isset($parsedUrl['query'])) {
                    parse_str($parsedUrl['query'], $queryParams);
                    $token = $queryParams['token'] ?? '';
                }

                $logs[] = [
                    'ip'      => $rawIp,
                    'time'    => $time,
                    'method'  => $method,
                    'path'    => $parsedUrl['path'] ?? $url,
                    'url'     => $url,
                    'status'  => (int)$status,
                    'token'   => $token,
                    'ua'      => $ua,
                    'referer' => $referer
                ];
            }
        }
    }

    echo json_encode(['status' => 'success', 'data' => $logs]);
    exit;
}

// 2. 获取黑名单列表
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

    echo json_encode([
        'status' => 'success',
        'data' => [
            'ip'    => $getRules($ipFile, 'ip'),
            'ua'    => $getRules($uaFile, 'ua'),
            'token' => $getRules($tokenFile, 'token')
        ]
    ]);
    exit;
}

// 3. 执行封禁
if ($action === 'ban') {
    $type  = $inputData['type'] ?? ($_POST['type'] ?? '');
    $value = trim($inputData['value'] ?? ($_POST['value'] ?? ''));

    if (!in_array($type, ['ip', 'ua', 'token']) || empty($value)) {
        echo json_encode(['status' => 'error', 'message' => '参数不合法']);
        exit;
    }

    $targetFile = match($type) {
        'ip'    => $ipFile,
        'ua'    => $uaFile,
        'token' => $tokenFile
    };

    $ruleLine = formatRule($type, $value);
    $existing = file_exists($targetFile) ? file_get_contents($targetFile) : '';

    if (!str_contains($existing, $ruleLine)) {
        file_put_contents($targetFile, $ruleLine . "\n", FILE_APPEND);
        touch($reloadFlag);
    }

    echo json_encode(['status' => 'success', 'message' => "已成功封禁 {$type}: {$value}"]);
    exit;
}

// 4. 执行解封
if ($action === 'unban') {
    $type  = $inputData['type'] ?? ($_POST['type'] ?? '');
    $value = trim($inputData['value'] ?? ($_POST['value'] ?? ''));

    $targetFile = match($type) {
        'ip'    => $ipFile,
        'ua'    => $uaFile,
        'token' => $tokenFile,
        default => null
    };

    if (!$targetFile || !file_exists($targetFile)) {
        echo json_encode(['status' => 'error', 'message' => '找不到对应的规则文件']);
        exit;
    }

    $lines = file($targetFile, FILE_IGNORE_NEW_LINES);
    $newLines = [];
    foreach ($lines as $line) {
        $val = parseRuleValue($type, $line);
        if ($val !== null && $val === $value) {
            continue;
        }
        $newLines[] = $line;
    }

    file_put_contents($targetFile, implode("\n", $newLines) . "\n");
    touch($reloadFlag);

    echo json_encode(['status' => 'success', 'message' => '解封成功']);
    exit;
}

// 5. 新增路由：实时查询 SSL 证书状态
if ($action === 'cert_status') {
    echo json_encode(getSslCertificateInfo());
    exit;
}

// 6. 获取域名配置与状态
if ($action === 'get_domain') {
    $confPath = '/etc/nginx/conf.d/default.conf';
    $domain = '';
    if (file_exists($confPath)) {
        $conf = file_get_contents($confPath);
        if (preg_match('/server_name\s+([^;]+);/', $conf, $matches)) {
            $domain = trim($matches[1]);
        }
    }

    $certInfo = getSslCertificateInfo();

    echo json_encode([
        'domain'      => $domain,
        'cert_status' => $certInfo
    ]);
    exit;
}

// 7. 更新域名并触发证书申请
if ($action === 'update_domain' || $action === 'apply_cert') {
    $newDomain = trim($inputData['domain'] ?? ($_POST['domain'] ?? ''));
    if (empty($newDomain)) {
        echo json_encode(['status' => 'error', 'message' => '域名不能为空']);
        exit;
    }

    $confPath = '/etc/nginx/conf.d/default.conf';
    if (file_exists($confPath)) {
        $conf = file_get_contents($confPath);
        $newConf = preg_replace('/server_name\s+[^;]+;/', "server_name {$newDomain};", $conf);
        file_put_contents($confPath, $newConf);
    }

    file_put_contents('/etc/nginx/rules/.cert_flag', $newDomain);
    file_put_contents('/etc/nginx/rules/cert_status.json', json_encode([
        'status' => 'processing',
        'msg'    => '已提交申请，后台正在联系 Let\'s Encrypt 签发证书...'
    ]));

    echo json_encode(['status' => 'success', 'message' => '配置已更新，正在后台自动申请证书...']);
    exit;
}

echo json_encode(['status' => 'error', 'message' => '无效的操作指令']);
