<?php
session_start();
header('Content-Type: application/json; charset=utf-8');

define('ADMIN_PASSWORD_FILE', __DIR__ . '/../.admin_password');

// 鉴权：与统一登录状态保持一致
require_once __DIR__ . '/auth.php';
require_login();

$_SESSION['last_activity'] = time();

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
