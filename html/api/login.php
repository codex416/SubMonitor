<?php
// 【重要】必须放在文件最顶部，前面不能有任何字符、空格、空行、HTML
session_start();
header('Content-Type: application/json; charset=utf-8');

// ===================== 👇 请务必修改为你的管理密码 👇 =====================
define('ADMIN_PASSWORD', '在这里改成你自己的强密码');
// 会话有效期（秒），默认 24 小时 = 86400
define('SESSION_EXPIRE', 86400);
// 是否开启 IP/User-Agent 绑定（防会话劫持）
define('BIND_CLIENT_INFO', true);
// ===================== 👆 配置结束 👆 =====================


// ======================================
// 登录接口：POST 提交密码时校验并写入会话
// ======================================
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'])) {
    $inputPassword = trim($_POST['password'] ?? '');

    // 简单校验非空
    if ($inputPassword === '') {
        http_response_code(400);
        echo json_encode([
            'code' => 400,
            'msg'  => '请输入密码'
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }

    // 密码校验
    if ($inputPassword === ADMIN_PASSWORD) {
        // 登录成功，写入会话
        $_SESSION['is_logged_in'] = true;
        $_SESSION['login_time']    = time();

        // 可选：绑定客户端信息，降低会话劫持风险
        if (BIND_CLIENT_INFO) {
            $_SESSION['client_ip'] = $_SERVER['REMOTE_ADDR'] ?? '';
            $_SESSION['client_ua']  = $_SERVER['HTTP_USER_AGENT'] ?? '';
        }

        http_response_code(200);
        echo json_encode([
            'code' => 200,
            'msg'  => '登录成功'
        ], JSON_UNESCAPED_UNICODE);
        exit;
    } else {
        // 密码错误
        http_response_code(403);
        echo json_encode([
            'code' => 403,
            'msg'  => '密码错误，请重试'
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }
}


// ======================================
// 会话鉴权：供其他页面/接口引用，未登录直接拦截
// ======================================
function isAuthorized() {
    // 基础校验：登录标记 + 未过期
    $baseCheck = isset($_SESSION['is_logged_in'])
        && $_SESSION['is_logged_in'] === true
        && isset($_SESSION['login_time'])
        && (time() - $_SESSION['login_time']) < SESSION_EXPIRE;

    if (!$baseCheck) return false;

    // 可选：校验 IP/User-Agent 是否一致
    if (BIND_CLIENT_INFO) {
        $sameIp = ($_SESSION['client_ip'] ?? '') === ($_SERVER['REMOTE_ADDR'] ?? '');
        $sameUa = ($_SESSION['client_ua'] ?? '') === ($_SERVER['HTTP_USER_AGENT'] ?? '');
        return $sameIp && $sameUa;
    }

    return true;
}

// 未授权统一返回 401
if (!isAuthorized()) {
    // 清除无效会话
    session_unset();
    session_destroy();

    http_response_code(401);
    echo json_encode([
        'code' => 401,
        'msg'  => '未授权或会话已过期，请重新登录'
    ], JSON_UNESCAPED_UNICODE);
    exit;
}
