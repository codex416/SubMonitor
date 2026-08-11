<?php
// 引入鉴权文件，未登录会被直接拦截并返回 401
require_once __DIR__ . '/auth.php';

// 如果没有被 auth.php 拦截，说明已经处于登录状态
header('Content-Type: application/json');
echo json_encode([
    'code' => 200, 
    'message' => '已登录'
]);
?>
