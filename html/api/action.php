<?php
header('Content-Type: application/json; charset=utf-8');

// 统一解析来自前端的 JSON Body 或普通 GET/POST 参数
$rawInput = file_get_contents('php://input');
$inputData = json_decode($rawInput, true) ?: [];

$action = $_GET['action'] ?? ($inputData['action'] ?? ($_POST['action'] ?? ''));

$ipFile = '/etc/nginx/rules/ip_blacklist.conf';
$uaFile = '/etc/nginx/rules/ua_blacklist.conf';
$tokenFile = '/etc/nginx/rules/token_blacklist.conf';
$reloadFlag = '/etc/nginx/rules/.reload_flag';

// 辅助函数：格式化 Nginx 规则
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

// 辅助函数：从配置文件中还原出原始封禁目标值
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

// 1. 获取规则列表
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

// 2. 添加封禁
if ($action === 'ban') {
    $type = $inputData['type'] ?? '';
    $value = trim($inputData['value'] ?? '');

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
    
    // 检查是否已存在
    $existing = file_exists($targetFile) ? file_get_contents($targetFile) : '';
    if (str_contains($existing, $ruleLine)) {
        echo json_encode(['status' => 'success', 'message' => '该规则已存在']);
        exit;
    }

    // 追加规则并触发 reload 标记
    file_put_contents($targetFile, $ruleLine . "\n", FILE_APPEND);
    touch($reloadFlag);

    echo json_encode(['status' => 'success', 'message' => "已成功封禁 {$type}: {$value}"]);
    exit;
}

// 3. 解除封禁
if ($action === 'unban') {
    $type = $inputData['type'] ?? '';
    $value = trim($inputData['value'] ?? '');

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
            continue; // 跳过要删除的规则
        }
        $newLines[] = $line;
    }

    file_put_contents($targetFile, implode("\n", $newLines) . "\n");
    touch($reloadFlag);

    echo json_encode(['status' => 'success', 'message' => '解封成功']);
    exit;
}

// 4. 获取域名配置（兼容现有接口）
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

// 5. 更新域名并申请证书（兼容 update_domain 和 apply_cert 两种动作名）
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
