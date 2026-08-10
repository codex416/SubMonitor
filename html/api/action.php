<?php
header('Content-Type: application/json; charset=utf-8');

// 1. 自动探查并定位可写的 rules 目录路径
$possiblePaths = [
    __DIR__ . '/../../rules',
    __DIR__ . '/../rules',
    '/var/www/html/rules',
    '/var/www/rules'
];

$ruleDir = null;
foreach ($possiblePaths as $path) {
    $parent = dirname($path);
    if (is_dir($parent) && is_writable($parent)) {
        $ruleDir = $path;
        break;
    }
}

if (!$ruleDir) {
    $ruleDir = __DIR__ . '/../../rules';
}

if (!is_dir($ruleDir)) {
    @mkdir($ruleDir, 0777, true);
}

$ipFile    = $ruleDir . '/ip_blacklist.conf';
$tokenFile = $ruleDir . '/token_blacklist.conf';
$uaFile    = $ruleDir . '/ua_blacklist.conf';

// 初始化规则文件
foreach ([$ipFile, $tokenFile, $uaFile] as $f) {
    if (!file_exists($f)) {
        @file_put_contents($f, '');
    }
}

// 2. 兼容解析 POST JSON 与 Form 数据
$rawInput = file_get_contents('php://input');
$jsonData = json_decode($rawInput, true) ?? [];

$action = $_GET['action'] ?? $_POST['action'] ?? $jsonData['action'] ?? '';
$type   = $_POST['type']   ?? $jsonData['type']   ?? '';
$value  = trim($_POST['value'] ?? $_POST['target'] ?? $jsonData['value'] ?? $jsonData['target'] ?? '');

if (!$value) {
    echo json_encode(['status' => 'error', 'message' => '封禁目标不能为空']);
    exit;
}

// 兼容前端传参 (action: 'ban', type: 'ip'|'token'|'ua')
if ($action === 'ban') {
    if ($type === 'ip') $action = 'block_ip';
    elseif ($type === 'token') $action = 'block_token';
    elseif ($type === 'ua') $action = 'block_ua';
}

// 3. 处理 IP 封禁
if ($action === 'block_ip') {
    $line = "deny " . $value . ";\n";
    if (@file_put_contents($ipFile, $line, FILE_APPEND | LOCK_EX) !== false) {
        echo json_encode(['status' => 'success', 'message' => "IP [{$value}] 已成功封禁！"]);
    } else {
        echo json_encode(['status' => 'error', 'message' => '写入 IP 规则文件失败，请检查目录权限']);
    }
    exit;
}

// 4. 处理 Token 封禁
if ($action === 'block_token') {
    $line = 'if ($arg_token = "' . $value . '") { return 403; }' . "\n";
    if (@file_put_contents($tokenFile, $line, FILE_APPEND | LOCK_EX) !== false) {
        echo json_encode(['status' => 'success', 'message' => "Token 已成功封禁！"]);
    } else {
        echo json_encode(['status' => 'error', 'message' => '写入 Token 规则文件失败，请检查目录权限']);
    }
    exit;
}

// 5. 处理 UA 封禁
if ($action === 'block_ua') {
    $line = 'if ($http_user_agent ~* "' . $value . '") { return 403; }' . "\n";
    if (@file_put_contents($uaFile, $line, FILE_APPEND | LOCK_EX) !== false) {
        echo json_encode(['status' => 'success', 'message' => "User-Agent [{$value}] 已成功封禁！"]);
    } else {
        echo json_encode(['status' => 'error', 'message' => '写入 UA 规则文件失败，请检查目录权限']);
    }
    exit;
}

echo json_encode(['status' => 'error', 'message' => '未知的操作指令: ' . $action]);
