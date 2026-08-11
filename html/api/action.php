<?php
header('Content-Type: application/json; charset=utf-8');

// 1. 统一解析来自前端的 JSON Body、GET 与 POST 参数
$rawInput = file_get_contents('php://input');
$inputData = json_decode($rawInput, true) ?: [];

$action = $_GET['action'] ?? ($inputData['action'] ?? ($_POST['action'] ?? ''));

$ipFile = '/etc/nginx/rules/ip_blacklist.conf';
$uaFile = '/etc/nginx/rules/ua_blacklist.conf';
$tokenFile = '/etc/nginx/rules/token_blacklist.conf';
$reloadFlag = '/etc/nginx/rules/.reload_flag';
$logFile = '/var/log/nginx/access.log';

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

// ------------------- 路由处理 -------------------

// 1. 获取日志列表 (只读最后 300 行，极速解析)
if ($action === 'logs' || $action === 'get_logs') {
    $logs = [];
    if (file_exists($logFile)) {
        // 使用 tail 读取末尾 300 行
        $cmd = "tail -n 300 " . escapeshellarg($logFile);
        exec($cmd, $lines);
        $lines = array_reverse($lines);

        // 正则匹配标准 Nginx 格式: IP - - [TIME] "METHOD URL PROTOCOL" STATUS BYTES "REFERER" "UA"
        $pattern = '/^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+)\s+([^\s"]*)[^"]*" (\d+) \d+ "([^"]*)" "([^"]*)"/';

        foreach ($lines as $line) {
            if (preg_match($pattern, $line, $m)) {
                $rawIp = $m[1];
                $time = $m[2];
                $method = $m[3];
                $url = $m[4];
                $status = $m[5];
                $referer = $m[6] === '-' ? '' : $m[6];
                $ua = $m[7] === '-' ? '' : $m[7];

                // 从 URL 解析 token 参数
                $token = '';
                $parsedUrl = parse_url($url);
                if (isset($parsedUrl['query'])) {
                    parse_str($parsedUrl['query'], $queryParams);
                    $token = $queryParams['token'] ?? '';
                }

                $logs[] = [
                    'ip' => $rawIp,
                    'time' => $time,
                    'method' => $method,
                    'path' => $parsedUrl['path'] ?? $url,
                    'url' => $url,
                    'status' => (int)$status,
                    'token' => $token,
                    'ua' => $ua,
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
            'ip' => $getRules($ipFile, 'ip'),
            'ua' => $getRules($uaFile, 'ua'),
            'token' => $getRules($tokenFile, 'token')
        ]
    ]);
    exit;
}

// 3. 执行封禁
if ($action === 'ban') {
    $type = $inputData['type'] ?? ($_POST['type'] ?? '');
    $value = trim($inputData['value'] ?? ($_POST['value'] ?? ''));

    if (!in_array($type, ['ip', 'ua', 'token']) || empty($value)) {
        echo json_encode(['status' => 'error', 'message' => '参数不合法']);
        exit;
    }

    $targetFile = match($type) {
        'ip' => $ipFile,
        'ua' => $uaFile,
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
    $type = $inputData['type'] ?? ($_POST['type'] ?? '');
    $value = trim($inputData['value'] ?? ($_POST['value'] ?? ''));

    $targetFile = match($type) {
        'ip' => $ipFile,
        'ua' => $uaFile,
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

// 5. 获取域名与证书状态
if ($action === 'get_domain') {
    $confPath = '/etc/nginx/conf.d/default.conf';
    $domain = '';
    if (file_exists($confPath)) {
        $conf = file_get_contents($confPath);
        if (preg_match('/server_name\s+([^;]+);/', $conf, $matches)) {
            $domain = trim($matches[1]);
        }
    }

    $status = ['status' => 'idle', 'msg' => ''];
    $statusFile = '/etc/nginx/rules/cert_status.json';
    if (file_exists($statusFile)) {
        $status = json_decode(file_get_contents($statusFile), true) ?: $status;
    }

    echo json_encode(['domain' => $domain, 'cert_status' => $status]);
    exit;
}

// 6. 更新域名并触发证书申请
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
        'msg' => '已提交申请，后台正在联系 Let\'s Encrypt 签发证书...'
    ]));

    echo json_encode(['status' => 'success', 'message' => '配置已更新，正在后台自动申请证书...']);
    exit;
}

echo json_encode(['status' => 'error', 'message' => '无效的操作指令']);
