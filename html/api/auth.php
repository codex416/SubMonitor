<?php
session_start();
if (!isset($_SESSION['login_time']) || time() - $_SESSION['login_time'] > 86400) {
    $_SESSION['is_logged_in'] = false;
}

function is_logged_in(): bool {
    return isset($_SESSION['is_logged_in']) && $_SESSION['is_logged_in'] === true;
}

function require_login(): void {
    if (!is_logged_in()) {
        http_response_code(401);
        json_return(['status'=>'error','message'=>'请先登录'], 401);
    }
}

function json_return($data, $code=200) {
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}
