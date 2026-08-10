<?php
header('Content-Type: application/json; charset=utf-8');

$ruleDir = '/etc/nginx/rules';
if (!is_dir($ruleDir)) {
    @mkdir($ruleDir, 0755, true);
}

// 确保规则文件存在
$ipFile = $ruleDir . '/ip_blacklist.conf';
$tokenFile = $ruleDir . '/token_blacklist.conf';
$uaFile = $ruleDir . '/ua_blacklist.conf';

foreach ([$ipFile, $tokenFile, $uaFile] as $f) {
    if (!file_exists($f)) @file_put_contents($f, '');
}

$action = $_GET['action'] ?? '';
$target = trim($_POST['target'] ?? '');

if (!$target) {
    echo json_encode(['status' => 'error', 'msg' => '目标不能为空']);
    exit;
}

if ($action === 'block_ip') {
    $line = "deny " . $target . ";\n";
    file_put_contents($ipFile, $line, FILE_APPEND | LOCK_EX);
    echo json_encode(['status' => 'success', 'msg' => "IP {$target} 已加入封禁"]);
    exit;
}

if ($action === 'block_token') {
    $line = $target . " 1;\n";
    file_put_contents($tokenFile, $line, FILE_APPEND | LOCK_EX);
    echo json_encode(['status' => 'success', 'msg' => "Token 已加入封禁"]);
    exit;
}

echo json_encode(['status' => 'error', 'msg' => '未知的操作指令']);
