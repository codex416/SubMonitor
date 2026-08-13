<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// 保持与 login.php 一致的会话过期时间 (24小时)
if (!isset($_SESSION['login_time']) || time() - $_SESSION['login_time'] > 86400) {
    $_SESSION['is_logged_in'] = false;
}

function is_logged_in(): bool {
    $baseCheck = isset($_SESSION['is_logged_in']) && $_SESSION['is_logged_in'] === true;
    if (!$baseCheck) return false;

    // 可选：增加 IP 和 UA 校验防会话劫持（与 login.php 保持同步）
    $sameIp = ($_SESSION['client_ip'] ?? '') === ($_SERVER['REMOTE_ADDR'] ?? '');
    $sameUa = ($_SESSION['client_ua'] ?? '') === ($_SERVER['HTTP_USER_AGENT'] ?? '');
    
    return $sameIp && $sameUa;
}

function require_login(): void {
    if (!is_logged_in()) {
        http_response_code(401);
        json_return(['status'=>'error','message'=>'请先登录或会话已过期'], 401);
    }
}

function json_return($data, $code=200) {
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}
