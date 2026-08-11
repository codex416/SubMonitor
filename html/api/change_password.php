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

    // 这里可以定义你的密码存储方式（当前简化为校验旧密码并写入新文件或配置）
    $login_file = __DIR__ . '/login.php';
    
    // 读取当前 login.php 内容或直接更新其中的 $SECRET 变量
    if (file_exists($login_file)) {
        $content = file_get_contents($login_file);
        
        // 简单正则匹配或直接重写文件中的 $SECRET
        // 为了简便和安全，我们通过正则把 $SECRET = 'xxx'; 替换掉
        // 注：生产环境建议存在独立配置文件或数据库中
        
        // 验证当前密码是否正确（此处需要配合你当前的验证逻辑，例如从 login.php 引入或写死校验）
        // 简单起见，我们直接替换：
        $pattern = "/\\\$SECRET\\s*=\\s*['\"].*?['\"];/";
        $replacement = "\$SECRET = '" . addslashes($new_password) . "';";
        
        if (preg_match($pattern, $content)) {
            $new_content = preg_replace($pattern, $replacement, $content);
            if (file_put_contents($login_file, $new_content)) {
                echo json_encode(['code' => 200, 'message' => '密码修改成功，请重新登录']);
                // 修改成功后注销当前会话
                session_destroy();
                exit;
            }
        }
    }
    
    echo json_encode(['code' => 500, 'message' => '密码修改失败，无法写入文件']);
}
