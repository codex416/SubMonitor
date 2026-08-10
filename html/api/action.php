<?php
header('Content-Type: application/json; charset=utf-8');

$action = $_GET['action'] ?? ($_POST['action'] ?? '');

// 1. 获取当前绑定域名与证书申请状态
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

// 2. 保存新域名并自动申请/更新 SSL 证书
if ($action === 'update_domain') {
    $newDomain = trim($_POST['domain'] ?? '');
    if (empty($newDomain)) {
        echo json_encode(['status' => 'error', 'msg' => '域名不能为空']);
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
    
    echo json_encode(['status' => 'ok', 'msg' => '配置已更新，正在后台自动申请证书...']);
    exit;
}

echo json_encode(['status' => 'error', 'msg' => '无效的操作指令']);
