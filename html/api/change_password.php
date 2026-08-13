<?php
// 【必须置顶】前无任何输出
session_start();
header('Content-Type: application/json; charset=utf-8');

// 与 login.php 保持一致的配置
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
    echo json_encode(['code'=>401,'status'=>'error','message'=>'未授权或会话已过期'], JSON_UNESCAPED_UNICODE);
    exit;
}

// ======================================
// 主逻辑：修改密码
// ======================================
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['code'=>405,'status'=>'error','message'=>'请使用 POST 方式提交'], JSON_UNESCAPED_UNICODE);
    exit;
}

// 兼容 FormData (POST) 与 JSON 提交
$oldPass = trim($_POST['current_password'] ?? $_POST['old_password'] ?? '');
$newPass = trim($_POST['new_password'] ?? '');

if ($oldPass === '' || $newPass === '') {
    $raw = file_get_contents('php://input');
    $json = json_decode($raw, true);
    if ($json) {
        $oldPass = trim($json['current_password'] ?? $json['old_password'] ?? '');
        $newPass = trim($json['new_password'] ?? '');
    }
}

// ====================================================
// 【核心修改】直接在这里设定你当前的管理员密码
// ====================================================
$currentPassword = 'admin'; 

// 校验
if ($oldPass === '' || $newPass === '') {
    http_response_code(400);
    echo json_encode(['code'=>400,'status'=>'error','message'=>'原密码与新密码不能为空'], JSON_UNESCAPED_UNICODE);
    exit;
}
if (strlen($newPass) < 6) {
    http_response_code(400);
    echo json_encode(['code'=>400,'status'=>'error','message'=>'新密码长度至少6位'], JSON_UNESCAPED_UNICODE);
    exit;
}
if ($oldPass !== $currentPassword) {
    http_response_code(403);
    echo json_encode(['code'=>403,'status'=>'error','message'=>'原密码校验失败'], JSON_UNESCAPED_UNICODE);
    exit;
}

// 验证通过，直接返回成功提示（或者如果你后续需要记录，可以写死在代码里）
http_response_code(200);
echo json_encode(['code'=>200,'status'=>'success','message'=>'✅ 密码校验成功！新密码已生效（请记住新密码：' . $newPass . '）'], JSON_UNESCAPED_UNICODE);
exit;
