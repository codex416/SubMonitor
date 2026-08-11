<?php
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

$rulesDir = '/var/www/html/rules/';

$ipFile     = $rulesDir . 'ip_blacklist.conf';
$uaFile     = $rulesDir . 'ua_blacklist.conf';
$tokenFile  = $rulesDir . 'token_blacklist.conf';
$reloadFlag = $rulesDir . '.reload_flag';
$logFile    = $rulesDir . 'access.log';
$statusFile = $rulesDir . 'cert_status.json';
$certFlag   = $rulesDir . '.cert_flag';

function safeWriteFile($path, $content) {
    $dir = dirname($path);
    if (!is_dir($dir)) {
        @mkdir($dir, 0777, true);
    }
    return @file_put_contents($path, $content, LOCK_EX) !== false;
}

$action = $_REQUEST['action'] ?? '';

switch ($action) {
    case 'get_config':
        echo json_encode([
            'ip_blacklist' => file_exists($ipFile) ? file_get_contents($ipFile) : '',
            'ua_blacklist' => file_exists($uaFile) ? file_get_contents($uaFile) : '',
            'token_blacklist' => file_exists($tokenFile) ? file_get_contents($tokenFile) : '',
        ], JSON_UNESCAPED_UNICODE);
        break;

    case 'save_config':
        $ipContent = $_POST['ip_blacklist'] ?? '';
        $uaContent = $_POST['ua_blacklist'] ?? '';
        $tokenContent = $_POST['token_blacklist'] ?? '';

        if (safeWriteFile($ipFile, $ipContent) &&
            safeWriteFile($uaFile, $uaContent) &&
            safeWriteFile($tokenFile, $tokenContent)) {
            @touch($reloadFlag);
            echo json_encode(['success' => true, 'msg' => '保存成功']);
        } else {
            echo json_encode(['success' => false, 'msg' => '写入失败，请检查文件权限']);
        }
        break;

    case 'update_domain':
        $newDomain = trim($_POST['domain'] ?? '');
        if (!$newDomain) {
            echo json_encode(['success' => false, 'msg' => '域名不能为空']);
            exit;
        }

        if (!safeWriteFile($certFlag, $newDomain)) {
            echo json_encode(['success' => false, 'msg' => '权限不足！无法在目录创建标志文件。']);
            exit;
        }

        safeWriteFile($statusFile, json_encode([
            'status' => 'processing',
            'msg' => '正在向 Let\'s Encrypt 申请证书，请稍候...'
        ], JSON_UNESCAPED_UNICODE));

        echo json_encode(['success' => true, 'msg' => '证书申请任务已触发']);
        break;

    case 'cert_status':
        if (file_exists($statusFile)) {
            echo file_get_contents($statusFile);
        } else {
            echo json_encode(['status' => 'idle', 'msg' => '无进行中的任务']);
        }
        break;

    default:
        echo json_encode(['success' => false, 'msg' => '未知操作']);
        break;
}
