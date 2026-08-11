<?php
header('Content-Type: application/json; charset=utf-8');

$rulesDir     = '/etc/nginx/rules/';
$certFlag     = $rulesDir . '.cert_flag';
$reloadFlag   = $rulesDir . '.reload_flag';
$certStatus   = $rulesDir . 'cert_status.json';
$logFile      = '/var/log/nginx/sub_access.log'; // 保持与 logs.php 日志文件一致[cite: 23, 24]

$action = $_GET['action'] ?? ($_POST['action'] ?? '');

switch ($action) {
    case 'apply_cert':
        $domain = trim($_POST['domain'] ?? '');
        if (empty($domain)) {
            echo json_encode(['status' => 'error', 'msg' => '域名不能为空']);
            exit;
        }
        
        file_put_contents($certFlag, $domain);
        echo json_encode(['status' => 'success', 'msg' => '证书申请请求已提交，系统正在后台处理...']);
        break;

    case 'get_cert_status':
        if (file_exists($certStatus)) {
            $content = file_get_contents($certStatus);
            echo $content;
        } else {
            echo json_encode(['status' => 'idle', 'msg' => '暂无证书申请任务']);
        }
        break;

    case 'reload_nginx':
        file_put_contents($reloadFlag, '1');
        echo json_encode(['status' => 'success', 'msg' => '已发送重载配置指令']);
        break;

    case 'clear_logs':
        if (file_exists($logFile)) {
            file_put_contents($logFile, '');
        }
        echo json_encode(['status' => 'success', 'msg' => '日志已成功清空']);
        break;

    default:
        echo json_encode(['status' => 'error', 'msg' => '无效的操作指令']);
        break;
}
