<?php
// 【必须置顶】前无任何输出
session_start();
header('Content-Type: application/json; charset=utf-8');

// 与 login.php 保持一致的配置
define('ADMIN_PASSWORD_FILE', __DIR__ . '/../.admin_password');
define('SESSION_EXPIRE', 86400);
define('BIND_CLIENT_INFO', true);

/**
 * 统一鉴权 —— 与 login.php / auth.php 完全一致
 */
function isAuthorized() {
    $baseCheck = isset($_SESSION['is_logged_in'])
        && $_SESSION['is_logged_in'] === true
        && isset($_SESSION['login_time'])
        && (time() - $_SESSION['login_time']) < SESSION_EXPIRE;
    if (!$baseCheck) return false;

    if (BIND_CLIENT_INFO) {
        $sameIp = ($_SESSION['client_ip'] ?? '') === ($_SERVER['REMOTE_ADDR'] ?? '');
        $sameUa = ($_SESSION['client_ua'] ?? '') === ($_SERVER['HTTP_USER_AGENT'] ?? '');
        return $sameIp && $sameUa;
    }
    return true;
}

// 未登录拦截
if (!isAuthorized()) {
    session_unset(); session_destroy();
    http_response_code(401);
    echo json_encode(['code'=>401,'msg'=>'未授权或会话已过期'], JSON_UNESCAPED_UNICODE);
    exit;
}

// ======================================
// 主逻辑：修改密码
// ======================================
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['code'=>405,'msg'=>'请使用 POST 方式提交'], JSON_UNESCAPED_UNICODE);
    exit;
}

// 优先读取 JSON / 兼容表单
$raw = file_get_contents('php://input');
$json = json_decode($raw, true);
$oldPass = trim($json['old_password'] ?? $_POST['old_password'] ?? '');
$newPass = trim($json['new_password'] ?? $_POST['new_password'] ?? '');

// 读取当前密码（兼容硬写/文件两种方式）
$currentPassword = '';
if (file_exists(ADMIN_PASSWORD_FILE)) {
    $currentPassword = trim(file_get_contents(ADMIN_PASSWORD_FILE));
} else {
    // 与 login.php 里密码保持一致，建议统一改用 .admin_password 文件
    $currentPassword = '在这里改成你当前使用的管理密码';
}

// 校验
if ($oldPass === '' || $newPass === '') {
    http_response_code(400);
    echo json_encode(['code'=>400,'msg'=>'原密码与新密码不能为空'], JSON_UNESCAPED_UNICODE);
    exit;
}
if (strlen($newPass) < 6) {
    http_response_code(400);
    echo json_encode(['code'=>400,'msg'=>'新密码长度至少6位'], JSON_UNESCAPED_UNICODE);
    exit;
}
if ($oldPass !== $currentPassword) {
    http_response_code(403);
    echo json_encode(['code'=>403,'msg'=>'原密码校验失败'], JSON_UNESCAPED_UNICODE);
    exit;
}

// 写入新密码到隐藏文件（更安全，不进代码仓库）
if (file_put_contents(ADMIN_PASSWORD_FILE, $newPass)) {
    chmod(ADMIN_PASSWORD_FILE, 0600);
    // 可选：同时更新 session 标记，保持登录状态
    http_response_code(200);
    echo json_encode(['code'=>200,'msg'=>'密码修改成功，请牢记新密码'], JSON_UNESCAPED_UNICODE);
} else {
    http_response_code(500);
    echo json_encode(['code'=>500,'msg'=>'密码写入失败，请检查目录权限'], JSON_UNESCAPED_UNICODE);
}
exit;
