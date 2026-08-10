<?php
header('Content-Type: application/json; charset=utf-8');

// 1. 使用项目内部相对路径，确保在 PHP 容器中有写权限
$ruleDir = __DIR__ . '/../../rules';
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

// 2. 兼容表单提交和 JSON 格式提交
$rawInput = file_get_contents('php://input');
$jsonData = json_decode($rawInput, true) ?? [];

$action = $_GET['action'] ?? $_POST['action'] ?? $jsonData['action'] ?? '';
$target = trim($_POST['target'] ?? $jsonData['target'] ?? '');

if (!$target) {
    echo json_encode(['status' => 'error', 'msg' => '目标参数不能为空']);
    exit;
}

// 3. 处理 IP 封禁 (Nginx location 语法: deny x.x.x.x;)
if ($action === 'block_ip') {
    $line = "deny " . $target . ";\n";
    if (@file_put_contents($ipFile, $line, FILE_APPEND | LOCK_EX) !== false) {
        echo json_encode(['status' => 'success', 'msg' => "IP [{$target}] 已成功加入封禁名单！"]);
    } else {
        echo json_encode(['status' => 'error', 'msg' => '写入 IP 规则文件失败，请检查 rules 目录权限']);
    }
    exit;
}

// 4. 处理 Token 封禁 (Nginx location 语法: if ($arg_token = "xxx") { return 403; })
if ($action === 'block_token') {
    $line = 'if ($arg_token = "' . $target . '") { return 403; }' . "\n";
    if (@file_put_contents($tokenFile, $line, FILE_APPEND | LOCK_EX) !== false) {
        echo json_encode(['status' => 'success', 'msg' => "Token 已成功加入封禁名单！"]);
    } else {
        echo json_encode(['status' => 'error', 'msg' => '写入 Token 规则文件失败，请检查 rules 目录权限']);
    }
    exit;
}

// 5. 处理 UA 封禁 (Nginx location 语法: if ($http_user_agent ~* "xxx") { return 403; })
if ($action === 'block_ua') {
    $line = 'if ($http_user_agent ~* "' . $target . '") { return 403; }' . "\n";
    if (@file_put_contents($uaFile, $line, FILE_APPEND | LOCK_EX) !== false) {
        echo json_encode(['status' => 'success', 'msg' => "User-Agent [{$target}] 已成功加入封禁名单！"]);
    } else {
        echo json_encode(['status' => 'error', 'msg' => '写入 UA 规则文件失败，请检查 rules 目录权限']);
    }
    exit;
}

echo json_encode(['status' => 'error', 'msg' => '未知的操作指令: ' . $action]);
