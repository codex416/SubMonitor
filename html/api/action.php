<?php
header('Content-Type: application/json; charset=utf-8');

$ruleDir = '/etc/nginx/rules';

if (!is_dir($ruleDir)) {
    @mkdir($ruleDir, 0777, true);
}

$ipFile    = $ruleDir . '/ip_blacklist.conf';
$tokenFile = $ruleDir . '/token_blacklist.conf';
$uaFile    = $ruleDir . '/ua_blacklist.conf';
$flagFile  = $ruleDir . '/.reload_flag';

// 初始化规则文件
foreach ([$ipFile, $tokenFile, $uaFile] as $f) {
    if (!file_exists($f)) {
        @file_put_contents($f, '');
    }
}

// 解析请求参数
$rawInput = file_get_contents('php://input');
$jsonData = json_decode($rawInput, true) ?? [];

$action = $_GET['action'] ?? $_POST['action'] ?? $jsonData['action'] ?? '';
$type   = $_POST['type']   ?? $jsonData['type']   ?? '';
$value  = trim($_POST['value'] ?? $_POST['target'] ?? $jsonData['value'] ?? $jsonData['target'] ?? '');

if (!$value) {
    echo json_encode(['status' => 'error', 'message' => '封禁目标不能为空']);
    exit;
}

// 适配前端指令
if ($action === 'ban') {
    if ($type === 'ip') $action = 'block_ip';
    elseif ($type === 'token') $action = 'block_token';
    elseif ($type === 'ua') $action = 'block_ua';
}

// 辅助函数：生成 reload 标记
function triggerNginxReload($flagFile) {
    @file_put_contents($flagFile, '1');
}

// 1. 处理 IP 封禁
if ($action === 'block_ip') {
    $line = "deny " . $value . ";\n";
    if (@file_put_contents($ipFile, $line, FILE_APPEND | LOCK_EX) !== false) {
        triggerNginxReload($flagFile);
        echo json_encode(['status' => 'success', 'message' => "IP [{$value}] 已封禁，Nginx 已自动重载！"]);
    } else {
        echo json_encode(['status' => 'error', 'message' => '写入失败，请检查目录权限']);
    }
    exit;
}

// 2. 处理 Token 封禁
if ($action === 'block_token') {
    $line = 'if ($arg_token = "' . $value . '") { return 403; }' . "\n";
    if (@file_put_contents($tokenFile, $line, FILE_APPEND | LOCK_EX) !== false) {
        triggerNginxReload($flagFile);
        echo json_encode(['status' => 'success', 'message' => "Token 已封禁，Nginx 已自动重载！"]);
    } else {
        echo json_encode(['status' => 'error', 'message' => '写入失败，请检查目录权限']);
    }
    exit;
}

// 3. 处理 UA 封禁
if ($action === 'block_ua') {
    $line = 'if ($http_user_agent ~* "' . $value . '") { return 403; }' . "\n";
    if (@file_put_contents($uaFile, $line, FILE_APPEND | LOCK_EX) !== false) {
        triggerNginxReload($flagFile);
        echo json_encode(['status' => 'success', 'message' => "User-Agent 已封禁，Nginx 已自动重载！"]);
    } else {
        echo json_encode(['status' => 'error', 'message' => '写入失败，请检查目录权限']);
    }
    exit;
}

echo json_encode(['status' => 'error', 'message' => '未知的操作指令: ' . $action]);
