<?php
header('Content-Type: application/json; charset=utf-8');

// 1. 根据 docker-compose.yml 的挂载路径，直接指定 /etc/nginx/rules
$ruleDir = '/etc/nginx/rules';

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

// 2. 解析前端 JSON 请求体
$rawInput = file_get_contents('php://input');
$jsonData = json_decode($rawInput, true) ?? [];

$action = $_GET['action'] ?? $_POST['action'] ?? $jsonData['action'] ?? '';
$type   = $_POST['type']   ?? $jsonData['type']   ?? '';
$value  = trim($_POST['value'] ?? $_POST['target'] ?? $jsonData['value'] ?? $jsonData['target'] ?? '');

if (!$value) {
    echo json_encode(['status' => 'error', 'message' => '封禁目标不能为空']);
    exit;
}

// 适配前端 index.html 的 banTarget(type, value) 函数
if ($action === 'ban') {
    if ($type === 'ip') $action = 'block_ip';
    elseif ($type === 'token') $action = 'block_token';
    elseif ($type === 'ua') $action = 'block_ua';
}

// 3. 处理 IP 封禁
if ($action === 'block_ip') {
    $line = "deny " . $value . ";\n";
    if (@file_put_contents($ipFile, $line, FILE_APPEND | LOCK_EX) !== false) {
        echo json_encode(['status' => 'success', 'message' => "IP [{$value}] 已成功加入封禁名单！"]);
    } else {
        echo json_encode(['status' => 'error', 'message' => '写入失败，请在宿主机执行 chmod -R 777 rules']);
    }
    exit;
}

// 4. 处理 Token 封禁
if ($action === 'block_token') {
    $line = 'if ($arg_token = "' . $value . '") { return 403; }' . "\n";
    if (@file_put_contents($tokenFile, $line, FILE_APPEND | LOCK_EX) !== false) {
        echo json_encode(['status' => 'success', 'message' => "Token 已成功加入封禁名单！"]);
    } else {
        echo json_encode(['status' => 'error', 'message' => '写入失败，请在宿主机执行 chmod -R 777 rules']);
    }
    exit;
}

// 5. 处理 UA 封禁
if ($action === 'block_ua') {
    $line = 'if ($http_user_agent ~* "' . $value . '") { return 403; }' . "\n";
    if (@file_put_contents($uaFile, $line, FILE_APPEND | LOCK_EX) !== false) {
        echo json_encode(['status' => 'success', 'message' => "User-Agent [{$value}] 已成功加入封禁名单！"]);
    } else {
        echo json_encode(['status' => 'error', 'message' => '写入失败，请在宿主机执行 chmod -R 777 rules']);
    }
    exit;
}

echo json_encode(['status' => 'error', 'message' => '未知的操作指令: ' . $action]);
