<?php
// 【重要】必须放在文件最顶部，前面不能有任何输出、空格、空行
session_start();
header('Content-Type: application/json; charset=utf-8');

// 引入与 login.php 完全一致的配置与鉴权函数
define('SESSION_EXPIRE', 86400);
define('BIND_CLIENT_INFO', true);

/**
 * 统一鉴权函数 —— 与 login.php 逻辑完全一致
 */
function isAuthorized() {
    // 基础校验：登录标记 + 未过期
    $baseCheck = isset($_SESSION['is_logged_in'])
        && $_SESSION['is_logged_in'] === true
        && isset($_SESSION['login_time'])
        && (time() - $_SESSION['login_time']) < SESSION_EXPIRE;

    if (!$baseCheck) return false;

    // 可选：校验 IP/User-Agent 防会话劫持（与 login.php 同步开关）
    if (BIND_CLIENT_INFO) {
        $sameIp = ($_SESSION['client_ip'] ?? '') === ($_SERVER['REMOTE_ADDR'] ?? '');
        $sameUa = ($_SESSION['client_ua'] ?? '') === ($_SERVER['HTTP_USER_AGENT'] ?? '');
        return $sameIp && $sameUa;
    }

    return true;
}

// ======================================
// 接口主逻辑：返回当前登录状态与信息
// ======================================
if (isAuthorized()) {
    // 已登录：返回状态 + 基础信息
    http_response_code(200);
    echo json_encode([
        'code' => 200,
        'msg'  => '已登录',
        'data' => [
            'is_logged_in' => true,
            'login_time'   => $_SESSION['login_time'],
            'expires_in'   => SESSION_EXPIRE - (time() - $_SESSION['login_time'])
        ]
    ], JSON_UNESCAPED_UNICODE);
} else {
    // 未登录/已过期：清除无效会话 + 返回统一格式
    session_unset();
    session_destroy();

    http_response_code(401);
    echo json_encode([
        'code' => 401,
        'msg'  => '未授权或会话已过期，请重新登录'
    ], JSON_UNESCAPED_UNICODE);
}
