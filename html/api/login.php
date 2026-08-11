<?php
session_start();
$SECRET = '你的后台管理密码'; // 请在这里改成你的密码

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['password']) && $_POST['password'] === $SECRET) {
        $_SESSION['is_logged_in'] = true;
        echo json_encode(['code' => 200, 'message' => '登录成功']);
    } else {
        echo json_encode(['code' => 403, 'message' => '密码错误']);
    }
}
