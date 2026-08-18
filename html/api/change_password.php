<?php
session_start();
header('Content-Type: application/json; charset=utf-8');

define('ADMIN_PASSWORD_FILE', __DIR__ . '/../.admin_password');

// 鉴权：与系统登录状态保持一致
define('SESSION_EXPIRE', 86400);
define('BIND_CLIENT_INFO', true);

$baseCheck = isset($_SESSION['is_logged_in'])
    && $_SESSION['is_logged_in'] === true
    && isset($_SESSION['login_time'])
    && (time() - $_SESSION['login_time']) < SESSION_EXPIRE;

if (!$baseCheck) {
    session_unset();
    session_destroy();
    http_response_code(401);
    echo json_encode(['code'=>401,'message'=>'未授权或会话已过期'], JSON_UNESCAPED_UNICODE);
    exit;
}

if (BIND_CLIENT_INFO) {
    $sameIp = ($_SESSION['client_ip'] ?? '') === ($_SERVER['REMOTE_ADDR'] ?? '');
    $sameUa = ($_SESSION['client_ua'] ?? '') === ($_SERVER['HTTP_USER_AGENT'] ?? '');
    if (!$sameIp || !$sameUa) {
        session_unset();
        session_destroy();
        http_response_code(401);
        echo json_encode(['code'=>401,'message'=>'未授权或会话已失效'], JSON_UNESCAPED_UNICODE);
        exit;
    }
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') exit;

$oldPass = trim($_POST['current_password'] ?? '');
$newPass = trim($_POST['new_password'] ?? '');

$currentStored = file_exists(ADMIN_PASSWORD_FILE) ? trim(file_get_contents(ADMIN_PASSWORD_FILE)) : 'admin';

if ($oldPass !== $currentStored) {
    http_response_code(403);
    echo json_encode(['code'=>403,'message'=>'原密码校验失败'], JSON_UNESCAPED_UNICODE);
    exit;
}

if (strlen($newPass) < 6) {
    http_response_code(400);
    echo json_encode(['code'=>400,'message'=>'新密码至少6位'], JSON_UNESCAPED_UNICODE);
    exit;
}

if (file_put_contents(ADMIN_PASSWORD_FILE, $newPass)) {
    echo json_encode(['code'=>200,'message'=>'修改成功'], JSON_UNESCAPED_UNICODE);
} else {
    http_response_code(500);
    echo json_encode(['code'=>500,'message'=>'写入失败'], JSON_UNESCAPED_UNICODE);
}
