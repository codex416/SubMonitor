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

// 确保规则文件存在
foreach ([$ipFile, $tokenFile, $uaFile] as $f) {
    if (!file_exists($f)) {
        @file_put_contents($f, '');
    }
}

// 解析输入数据
$rawInput = file_get_contents('php://input');
$jsonData = json_decode($rawInput, true) ?? [];

$action = $_REQUEST['action'] ?? $jsonData['action'] ?? '';
$type   = $_REQUEST['type']   ?? $jsonData['type']   ?? '';
$value  = trim($_REQUEST['value'] ?? $_REQUEST['target'] ?? $jsonData['value'] ?? $jsonData['target'] ?? '');

function triggerNginxReload($flagFile) {
    @file_put_contents($flagFile, '1');
}

// 1. 获取所有当前封禁列表 (IP / Token / UA)
if ($action === 'list' || $action === 'get_rules') {
    $ips = [];
    $tokens = [];
    $uas = [];

    if (file_exists($ipFile)) {
        $lines = file($ipFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            if (preg_match('/deny\s+([^;]+);/i', trim($line), $m)) {
                $ips[] = trim($m[1]);
            }
        }
    }

    if (file_exists($tokenFile)) {
        $lines = file($tokenFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            if (preg_match('/\$arg_token\s*=\s*"([^"]+)"/i', trim($line), $m)) {
                $tokens[] = trim($m[1]);
            }
        }
    }

    if (file_exists($uaFile)) {
        $lines = file($uaFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            if (preg_match('/\$http_user_agent\s*~\*\s*"([^"]+)"/i', trim($line), $m)) {
                $uas[] = trim($m[1]);
            }
        }
    }

    echo json_encode([
        'status' => 'success',
        'data' => [
            'ip'    => array_values(array_unique($ips)),
            'token' => array_values(array_unique($tokens)),
            'ua'    => array_values(array_unique($uas))
        ]
    ]);
    exit;
}

// 2. 执行封禁 (支持从日志一键封禁，也支持手动主动作输入添加)
if ($action === 'ban' || $action === 'block') {
    if (!$value || !$type) {
        echo json_encode(['status' => 'error', 'message' => '参数不完整']);
        exit;
    }

    // 适配旧前端 block_ip / block_token 命名
    if ($type === 'block_ip') $type = 'ip';
    if ($type === 'block_token') $type = 'token';
    if ($type === 'block_ua') $type = 'ua';

    if ($type === 'ip') {
        $line = "deny " . $value . ";\n";
        @file_put_contents($ipFile, $line, FILE_APPEND | LOCK_EX);
    } elseif ($type === 'token') {
        $line = 'if ($arg_token = "' . $value . '") { return 403; }' . "\n";
        @file_put_contents($tokenFile, $line, FILE_APPEND | LOCK_EX);
    } elseif ($type === 'ua') {
        $line = 'if ($http_user_agent ~* "' . $value . '") { return 403; }' . "\n";
        @file_put_contents($uaFile, $line, FILE_APPEND | LOCK_EX);
    } else {
        echo json_encode(['status' => 'error', 'message' => '不支持的封禁类型']);
        exit;
    }

    triggerNginxReload($flagFile);
    echo json_encode(['status' => 'success', 'message' => "已成功加入封禁名单！"]);
    exit;
}

// 3. 执行解封 (移除指定规则)
if ($action === 'unban' || $action === 'unblock') {
    if (!$value || !$type) {
        echo json_encode(['status' => 'error', 'message' => '参数不完整']);
        exit;
    }

    $targetFile = null;
    if ($type === 'ip') $targetFile = $ipFile;
    if ($type === 'token') $targetFile = $tokenFile;
    if ($type === 'ua') $targetFile = $uaFile;

    if ($targetFile && file_exists($targetFile)) {
        $lines = file($targetFile, FILE_IGNORE_NEW_LINES);
        $newLines = [];
        foreach ($lines as $line) {
            // 过滤掉包含解封目标的行
            if (strpos($line, $value) === false && trim($line) !== '') {
                $newLines[] = $line;
            }
        }
        $content = count($newLines) > 0 ? implode("\n", $newLines) . "\n" : '';
        file_put_contents($targetFile, $content, LOCK_EX);
        
        triggerNginxReload($flagFile);
        echo json_encode(['status' => 'success', 'message' => "已成功解封！"]);
        exit;
    }

    echo json_encode(['status' => 'error', 'message' => '规则文件未找到']);
    exit;
}

echo json_encode(['status' => 'error', 'message' => '未知的操作指令']);
