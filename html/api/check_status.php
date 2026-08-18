<?php
// 【必须置顶】前无任何输出
session_start();
header('Content-Type: application/json; charset=utf-8');

// 与 login.php 保持一致的配置
define('SESSION_IDLE_EXPIRE', 7200);
define('SESSION_ABSOLUTE_EXPIRE', 604800);
define('BIND_CLIENT_INFO', true);

/**
 * 统一鉴权 —— 与 login.php / auth.php 完全一致
 */
function isAuthorized() {
    $baseCheck = isset($_SESSION['is_logged_in'])
        && $_SESSION['is_logged_in'] === true
        && isset($_SESSION['login_time'])
        && isset($_SESSION['last_activity'])
        && (time() - $_SESSION['login_time']) < SESSION_ABSOLUTE_EXPIRE
        && (time() - $_SESSION['last_activity']) < SESSION_IDLE_EXPIRE;
    if (!$baseCheck) return false;

    if (BIND_CLIENT_INFO) {
        $sameIp = ($_SESSION['client_ip'] ?? '') === ($_SERVER['REMOTE_ADDR'] ?? '');
        $sameUa = ($_SESSION['client_ua'] ?? '') === ($_SERVER['HTTP_USER_AGENT'] ?? '');
        return $sameIp && $sameUa;
    }
    return true;
}

// ======================================
// 主逻辑：查询系统/登录状态
// ======================================
if (isAuthorized()) {
    $_SESSION['last_activity'] = time();
    $idleRemain = SESSION_IDLE_EXPIRE - (time() - ($_SESSION['last_activity'] ?? time()));
    $absoluteRemain = SESSION_ABSOLUTE_EXPIRE - (time() - ($_SESSION['login_time'] ?? time()));
    $remain = min($idleRemain, $absoluteRemain);
    http_response_code(200);
    echo json_encode([
        'code' => 200,
        'msg'  => '运行正常',
        'data' => [
            'system_status' => 'online',
            'is_logged_in'  => true,
            'session_remain_seconds' => $remain > 0 ? $remain : 0,
            'timestamp'     => time()
        ]
    ], JSON_UNESCAPED_UNICODE);
} else {
    session_unset();
    session_destroy();
    http_response_code(401);
    echo json_encode([
        'code' => 401,
        'msg'  => '未登录或会话已过期',
        'data' => [
            'system_status' => 'online',
            'is_logged_in'  => false
        ]
    ], JSON_UNESCAPED_UNICODE);
}
exit;
