<?php
require_once __DIR__ . '/auth.php';

// 统一用容器内标准路径，确保100%能找到文件！
define('RULES_DIR',    '/etc/nginx/rules/');
define('NGINX_CONF',   '/etc/nginx/conf.d/default.conf');
define('SSL_DIR',      '/etc/nginx/ssl/');
define('LOGIN_PHP',    __DIR__ . '/login.php'); 
define('ADMIN_PASSWORD_FILE', __DIR__ . '/../.admin_password');

header('Content-Type: application/json; charset=utf-8');
require_login();

$inputData = json_decode(file_get_contents('php://input'), true) ?? [];
$action = trim($inputData['action'] ?? $_POST['action'] ?? $_GET['action'] ?? '');
$reloadFlag = RULES_DIR . '.reload_flag';

// 强制确保所有目录存在+可写
foreach ([RULES_DIR, SSL_DIR, dirname(NGINX_CONF), dirname(LOGIN_PHP), dirname(ADMIN_PASSWORD_FILE)] as $dir) {
    if (!is_dir($dir)) @mkdir($dir, 0777, true);
    @chmod($dir, 0777);
}

function safeWriteFile(string $filePath, string $content, bool $append = false): bool
{
    $dir = dirname($filePath);
    if (!is_dir($dir)) @mkdir($dir, 0777, true);
    @chmod($dir, 0777);
    if (file_exists($filePath)) @chmod($filePath, 0666);
    $flags = $append ? FILE_APPEND : 0;
    $result = @file_put_contents($filePath, $content, $flags);
    if ($result !== false) { @chmod($filePath, 0666); return true; }
    return false;
}

// ========================================================
// ✅ 更新反代域名
// ========================================================
if ($action === 'update_upstream') {
    $t = trim($inputData['target_domain'] ?? $_POST['target_domain'] ?? '');
    if (empty($t)) {
        echo json_encode(['status'=>'error','message'=>'域名不能为空'], JSON_UNESCAPED_UNICODE);
        exit;
    }
    $t = preg_replace('/^https?:\/\//i', '', $t);
    $t = rtrim($t, '/');
    if (!file_exists(NGINX_CONF)) {
        echo json_encode(['status'=>'error','message'=>'找不到Nginx配置文件：'.NGINX_CONF], JSON_UNESCAPED_UNICODE);
        exit;
    }
    $c = file_get_contents(NGINX_CONF);
    $c = preg_replace('/set\s+\$backend_url\s+"https?:\/\/[^"]+";/i', "set \$backend_url \"https://{$t}\";", $c);
    $c = preg_replace('/proxy_pass\s+https?:\/\/[^\/;\s]+;/i', "proxy_pass https://{$t};", $c);
    $c = preg_replace('/proxy_set_header\s+Host\s+[^;]+;/i', "proxy_set_header Host {$t};", $c);
    if (!safeWriteFile(NGINX_CONF, $c)) {
        echo json_encode(['status'=>'error','message'=>'写入配置失败，请检查权限'], JSON_UNESCAPED_UNICODE);
        exit;
    }
    @file_put_contents($reloadFlag, (string)time());
    @exec('nginx -s reload >/dev/null 2>&1 &');
    echo json_encode(['status'=>'success','message'=>"✅ 反代域名已更新：{$t}，配置已生效"], JSON_UNESCAPED_UNICODE);
    exit;
}

// ========================================================
// ✅ 更新域名 + 申请证书
// ========================================================
if ($action === 'apply_cert' || $action === 'update_domain') {
    $d = trim($inputData['domain'] ?? $_POST['domain'] ?? '');
    if (empty($d)) {
        echo json_encode(['status'=>'error','message'=>'域名不能为空'], JSON_UNESCAPED_UNICODE);
        exit;
    }
    if (!safeWriteFile(RULES_DIR.'.cert_flag', "{$d}\n")) {
        echo json_encode(['status'=>'error','message'=>'写入证书申请标记失败'], JSON_UNESCAPED_UNICODE);
        exit;
    }
    safeWriteFile(RULES_DIR.'cert_status.json', json_encode([
        'status'=>'processing','msg'=>"🔄 域名 {$d} 已提交，后台正在申请证书..."
    ], JSON_UNESCAPED_UNICODE));
    echo json_encode(['status'=>'success','message'=>"✅ 域名 {$d} 已保存，证书申请已在后台启动"], JSON_UNESCAPED_UNICODE);
    exit;
}

// ========================================================
// ✅ 获取证书状态（优先真实解析 cert.pem，彻底解决卡在 processing 的问题）
// ========================================================
if ($action === 'cert_status') {
    $certPath = SSL_DIR.'cert.pem';
    
    // 1. 优先检查真实证书文件是否存在
    if (file_exists($certPath)) {
        $pem = @file_get_contents($certPath);
        if ($pem && preg_match_all('/-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----/s', $pem, $m)) {
            $leaf = $m[0][0] ?? '';
            $certData = openssl_x509_parse($leaf);
            
            if ($certData) {
                $validToTime = $certData['validTo_time_t'] ?? time();
                $valid_to = date('Y-m-d H:i:s', $validToTime);
                $daysLeft = ceil(($validToTime - time()) / 86400);
                
                $issuer = $certData['issuer']['CN'] ?? ($certData['issuer']['organizationName'] ?? 'Let\'s Encrypt');
                
                // 尝试从 domain.conf 或证书 subject 中获取域名
                $domain = 'sub.befriends.wiki';
                if (file_exists(RULES_DIR.'domain.conf')) {
                    $d = trim(file_get_contents(RULES_DIR.'domain.conf'));
                    if (!empty($d)) $domain = $d;
                }
                if (empty($domain) && isset($certData['subject']['CN'])) {
                    $domain = $certData['subject']['CN'];
                }

                echo json_encode([
                    'status'=>'success',
                    'cert'=>[
                        'domain'=>$domain,
                        'issuer'=>$issuer,
                        'valid_to'=>$valid_to,
                        'days_left'=>$daysLeft > 0 ? $daysLeft : 0
                    ]
                ], JSON_UNESCAPED_UNICODE);
                exit;
            }
        }
    }

    // 2. 如果没有真实证书，再读取 cert_status.json 提示信息
    $certJson = @file_get_contents(RULES_DIR.'cert_status.json');
    if ($certJson) {
        $certData = json_decode($certJson, true);
        if ($certData) {
            echo json_encode([
                'status'=>'success',
                'cert'=>$certData['cert'] ?? null,
                'msg'=>$certData['msg'] ?? ''
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }
    }

    echo json_encode(['status'=>'success','cert'=>null,'msg'=>'证书尚未生成'], JSON_UNESCAPED_UNICODE);
    exit;
}

// ========================================================
// ✅ 更新黑名单
// ========================================================
if ($action === 'update_blacklist') {
    $ipList = $inputData['ip_blacklist'] ?? [];
    $uaList = $inputData['ua_blacklist'] ?? [];
    $tokenList = $inputData['token_blacklist'] ?? [];

    $ipContent = '# 禁止访问的IP'."\n".implode("\n", array_filter(array_map('trim', $ipList)))."\n";
    $uaContent = '# 禁止访问的客户端标识'."\n".implode("\n", array_filter(array_map('trim', $uaList)))."\n";
    $tokenContent = '# 禁止访问的Token'."\n".implode("\n", array_filter(array_map('trim', $tokenList)))."\n";

    $ok1 = safeWriteFile(RULES_DIR.'ip_blacklist.conf', $ipContent);
    $ok2 = safeWriteFile(RULES_DIR.'ua_blacklist.conf', $uaContent);
    $ok3 = safeWriteFile(RULES_DIR.'token_blacklist.conf', $tokenContent);

    @file_put_contents($reloadFlag, (string)time());
    @exec('nginx -s reload >/dev/null 2>&1 &');

    if ($ok1 && $ok2 && $ok3) {
        echo json_encode(['status'=>'success','message'=>'✅ 黑名单已更新，配置已生效'], JSON_UNESCAPED_UNICODE);
    } else {
        echo json_encode(['status'=>'error','message'=>'⚠️ 部分文件写入失败'], JSON_UNESCAPED_UNICODE);
    }
    exit;
}

// ========================================================
// ✅ 读取配置
// ========================================================
if ($action === 'get_config') {
    $domain = '';
    if (file_exists(NGINX_CONF) && preg_match('/proxy_pass\s+https?:\/\/([^\/;\s]+)/i', file_get_contents(NGINX_CONF), $m)) {
        $domain = trim($m[1]);
    }

    echo json_encode([
        'status'=>'success',
        'config'=>[
            'target_domain'=>$domain,
            'ip_blacklist'=>file_exists(RULES_DIR.'ip_blacklist.conf') ? array_filter(array_map('trim', explode("\n", ltrim(trim(file_get_contents(RULES_DIR.'ip_blacklist.conf')), '# ')))) : [],
            'ua_blacklist'=>file_exists(RULES_DIR.'ua_blacklist.conf') ? array_filter(array_map('trim', explode("\n", ltrim(trim(file_get_contents(RULES_DIR.'ua_blacklist.conf')), '# ')))) : [],
            'token_blacklist'=>file_exists(RULES_DIR.'token_blacklist.conf') ? array_filter(array_map('trim', explode("\n", ltrim(trim(file_get_contents(RULES_DIR.'token_blacklist.conf')), '# ')))) : [],
        ]
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

// ========================================================
// ✅ 修改密码
// ========================================================
if ($action === 'change_password') {
    $old = trim($inputData['old_password'] ?? $_POST['old_password'] ?? '');
    $new = trim($inputData['new_password'] ?? $_POST['new_password'] ?? '');
    
    $currentPassword = file_exists(ADMIN_PASSWORD_FILE) ? trim(file_get_contents(ADMIN_PASSWORD_FILE)) : '';

    if (empty($old) || empty($new)) {
        echo json_encode(['status'=>'error','message'=>'原密码与新密码不能为空'], JSON_UNESCAPED_UNICODE);
        exit;
    }
    if ($old !== $currentPassword) {
        echo json_encode(['status'=>'error','message'=>'原密码校验失败'], JSON_UNESCAPED_UNICODE);
        exit;
    }
    if (strlen($new) < 6) {
        echo json_encode(['status'=>'error','message'=>'新密码长度至少6位'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    if (file_put_contents(ADMIN_PASSWORD_FILE, $new)) {
        @chmod(ADMIN_PASSWORD_FILE, 0600);
        echo json_encode(['status'=>'success','message'=>'✅ 密码修改成功！下次登录用新密码'], JSON_UNESCAPED_UNICODE);
    } else {
        echo json_encode(['status'=>'error','message'=>'❌ 写入失败：请检查目录权限'], JSON_UNESCAPED_UNICODE);
    }
    exit;
}

// ========================================================
echo json_encode(['status'=>'error','message'=>'⚠️ 未知操作'], JSON_UNESCAPED_UNICODE);
