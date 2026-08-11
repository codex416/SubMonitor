<?php
session_start();
header('Content-Type: application/json');

// 校验是否已登录
if (!isset($_SESSION['is_logged_in']) || $_SESSION['is_logged_in'] !== true) {
    echo json_encode(['code' => 401, 'message' => '未登录或登录已过期']);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $current_password = $_POST['current_password'] ?? '';
    $new_password = $_POST['new_password'] ?? '';

    if (empty($current_password) || empty($new_password)) {
        echo json_encode(['code' => 400, 'message' => '密码不能为空']);
        exit;
    }

    $login_file = __DIR__ . '/login.php';
    
    if (file_exists($login_file)) {
        $content = file_get_contents($login_file);
        
        // 1. 提取当前的 $SECRET 值用于校验旧密码
        $pattern = "/\\\$SECRET\\s*=\\s*['\"](.*?)['\"];/";
        if (preg_match($pattern, $content, $matches)) {
            $stored_password = $matches[1];
            
            // 校验旧密码是否正确
            if ($current_password !== $stored_password) {
                echo json_encode(['code' => 400, 'message' => '当前密码（旧密码）输入错误']);
                exit;
            }
        } else {
            echo json_encode(['code' => 500, 'message' => '无法解析当前的密码配置']);
            exit;
        }
        
        // 2. 替换为新密码
        $replacement = "\$SECRET = '" . addslashes($new_password) . "';";
        $new_content = preg_replace($pattern, $replacement, $content);
        
        if (file_put_contents($login_file, $new_content)) {
            echo json_encode(['code' => 200, 'message' => '密码修改成功，请重新登录']);
            session_destroy();
            exit;
        }
    }
    
    echo json_encode(['code' => 500, 'message' => '密码修改失败，无法写入文件']);
}
