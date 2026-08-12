<?php
require_once __DIR__ . '/auth.php';

define('RULES_DIR',    '/etc/nginx/rules/');
define('NGINX_CONF',   '/etc/nginx/conf.d/default.conf');
define('SSL_DIR',      '/etc/nginx/ssl/');

// 统一 JSON 响应头
header('Content-Type: application/json; charset=utf-8');

// 仅登录可访问
require_login();

// 解析输入
$inputData = json_decode(file_get_contents('php://input'), true) ?? [];
$action = trim($inputData['action'] ?? $_POST['action'] ?? '');

$reloadFlag = RULES_DIR . '.reload_flag';

// 确保目录存在
foreach ([RULES_DIR, SSL_DIR, dirname(NGINX_CONF)] as $dir) {
    if (!is_dir($dir)) @mkdir($dir, 0777, true);
    @chmod($dir, 0777);
}

/**
 * 安全写入文件
 */
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
// 路由：更新反代域名
// ========================================================
if ($action==='update_upstream') {
    $t=trim($inputData['target_domain']??$_POST['target_domain']??'');
    if (empty($t)) { echo json_encode(['status'=>'error','message'=>'域名不能为空'],JSON_UNESCAPED_UNICODE); exit; }
    $t=preg_replace('/^https?:\/\//i','',$t); $t=rtrim($t,'/');
    if (!file_exists(NGINX_CONF)) { echo json_encode(['status'=>'error','message'=>'找不到Nginx配置文件'],JSON_UNESCAPED_UNICODE); exit; }
    $c=file_get_contents(NGINX_CONF);
    $c=preg_replace('/proxy_pass\s+[^;]+;/i',"proxy_pass https://{$t};",$c);
    $c=preg_replace('/proxy_set_header\s+Host\s+[^;]+;/i',"proxy_set_header Host {$t};",$c);
    $c=preg_replace('/proxy_ssl_name\s+[^;]+;/i',"proxy_ssl_name {$t};",$c);
    if (!safeWriteFile(NGINX_CONF,$c)) { echo json_encode(['status'=>'error','message'=>'写入配置失败，请检查挂载权限'],JSON_UNESCAPED_UNICODE); exit; }
    
    // ✅ 改用原生写入标记 + 立即重载 Nginx
    @file_put_contents($reloadFlag, (string)time());
    @exec('nginx -s reload >/dev/null 2>&1 &');
    echo json_encode(['status'=>'success','message'=>"反代域名已更新：{$t}，配置已生效"],JSON_UNESCAPED_UNICODE); exit;
}

// ========================================================
// 路由：申请证书 / 更新域名
// ========================================================
if ($action==='apply_cert' || $action==='update_domain') {
    $d=trim($inputData['domain']??$_POST['domain']??'');
    if (empty($d)) { echo json_encode(['status'=>'error','message'=>'域名不能为空'],JSON_UNESCAPED_UNICODE); exit; }
    safeWriteFile(RULES_DIR.'.cert_flag',"{$d}\n");
    safeWriteFile(RULES_DIR.'cert_status.json',json_encode(['status'=>'processing','msg'=>"域名 {$d} 已提交，后台正在申请证书..."]));
    echo json_encode(['status'=>'success','message'=>"域名 {$d} 已保存，证书申请已在后台启动"],JSON_UNESCAPED_UNICODE); exit;
}

// ========================================================
// 路由：证书状态
// ========================================================
if ($action==='cert_status') {
    $certJson = @file_get_contents(RULES_DIR.'cert_status.json');
    if ($certJson) {
        $certData = json_decode($certJson, true);
        if ($certData && ($certData['status']==='success' || isset($certData['cert']))) {
            echo json_encode(['status'=>'success','cert'=>$certData['cert']??null,'msg'=>$certData['msg']??''],JSON_UNESCAPED_UNICODE);
            exit;
        }
    }

    // 读取配置中的域名并解析证书
    if (file_exists(NGINX_CONF) && preg_match('/proxy_pass\s+https?:\/\/([^\/;\s]+)/i',file_get_contents(NGINX_CONF),$m)) $u=trim($m[1]);
    if (empty($u)) { echo json_encode(['status'=>'success','cert'=>null,'msg'=>'尚未配置域名'],JSON_UNESCAPED_UNICODE); exit; }

    $certPath = SSL_DIR.'cert.pem';
    if (!file_exists($certPath)) { echo json_encode(['status'=>'success','cert'=>null,'msg'=>'证书尚未生成'],JSON_UNESCAPED_UNICODE); exit; }

    $pem = @file_get_contents($certPath);
    if (!$pem) { echo json_encode(['status'=>'success','cert'=>null,'msg'=>'证书文件读取失败'],JSON_UNESCAPED_UNICODE); exit; }

    // 解析证书有效期
    $certs = [];
    if (preg_match_all('/-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----/s',$pem,$m)) {
        $certs = $m[0];
    }
    $leaf = $certs[0] ?? '';
    $valid_to = $issuer = '';

    // 提取有效期
    if (preg_match('/Not After\s*:\s*(.+)/',$leaf,$m)) $valid_to = trim($m[1]);
    // 提取颁发者
    if (preg_match('/Issuer\s*=\s*\/?CN\s*=\s*([^,\n\/]+)/',$leaf,$m)) $issuer = trim($m[1]);
    if (empty($issuer) && preg_match('/Issuer:\s*CN=([^,\n]+)/',$leaf,$m)) $issuer = trim($m[1]);

    // 格式化日期
    $ts = $valid_to ? strtotime($valid_to) : 0;
    $daysLeft = $ts ? ceil(($ts - time())/86400) : 0;
    $fmtDate = $ts ? date('Y-m-d H:i:s',$ts) : '';

    echo json_encode([
        'status'=>'success',
        'cert'=>[
            'domain'=>$u,
            'issuer'=>$issuer?: '未知',
            'valid_to'=>$fmtDate,
            'days_left'=>$daysLeft>0 ? $daysLeft : 0
        ]
    ],JSON_UNESCAPED_UNICODE); exit;
}

// ========================================================
// 路由：更新黑名单
// ========================================================
if ($action==='update_blacklist') {
    $ipList = $inputData['ip_blacklist'] ?? [];
    $uaList = $inputData['ua_blacklist'] ?? [];
    $tokenList = $inputData['token_blacklist'] ?? [];

    $ipContent = '# 禁止访问的IP'."\n".implode("\n",array_filter(array_map('trim',$ipList)))."\n";
    $uaContent = '# 禁止访问的客户端标识'."\n".implode("\n",array_filter(array_map('trim',$uaList)))."\n";
    $tokenContent = '# 禁止访问的Token'."\n".implode("\n",array_filter(array_map('trim',$tokenList)))."\n";

    $ok1 = safeWriteFile(RULES_DIR.'ip_blacklist.conf',$ipContent);
    $ok2 = safeWriteFile(RULES_DIR.'ua_blacklist.conf',$uaContent);
    $ok3 = safeWriteFile(RULES_DIR.'token_blacklist.conf',$tokenContent);

    @file_put_contents($reloadFlag, (string)time());
    @exec('nginx -s reload >/dev/null 2>&1 &');

    if ($ok1 && $ok2 && $ok3) {
        echo json_encode(['status'=>'success','message'=>'黑名单已更新，配置已生效'],JSON_UNESCAPED_UNICODE);
    } else {
        echo json_encode(['status'=>'error','message'=>'部分文件写入失败'],JSON_UNESCAPED_UNICODE);
    }
    exit;
}

// ========================================================
// 路由：读取配置
// ========================================================
if ($action==='get_config') {
    $domain = '';
    if (file_exists(NGINX_CONF) && preg_match('/proxy_pass\s+https?:\/\/([^\/;\s]+)/i',file_get_contents(NGINX_CONF),$m)) {
        $domain = trim($m[1]);
    }

    echo json_encode([
        'status'=>'success',
        'config'=>[
            'target_domain'=>$domain,
            'ip_blacklist'=>file_exists(RULES_DIR.'ip_blacklist.conf') ? array_filter(array_map('trim',explode("\n",ltrim(trim(file_get_contents(RULES_DIR.'ip_blacklist.conf')),'# ')))) : [],
            'ua_blacklist'=>file_exists(RULES_DIR.'ua_blacklist.conf') ? array_filter(array_map('trim',explode("\n",ltrim(trim(file_get_contents(RULES_DIR.'ua_blacklist.conf')),'# ')))) : [],
            'token_blacklist'=>file_exists(RULES_DIR.'token_blacklist.conf') ? array_filter(array_map('trim',explode("\n",ltrim(trim(file_get_contents(RULES_DIR.'token_blacklist.conf')),'# ')))) : [],
        ]
    ],JSON_UNESCAPED_UNICODE); exit;
}

// ========================================================
// 路由：修改密码
// ========================================================
if ($action==='change_password') {
    $pwdFile = RULES_DIR.'.htpasswd';
    $old = trim($inputData['old_password'] ?? '');
    $new = trim($inputData['new_password'] ?? '');

    if (empty($old) || empty($new)) {
        echo json_encode(['status'=>'error','message'=>'旧密码与新密码不能为空'],JSON_UNESCAPED_UNICODE); exit;
    }
    if (strlen($new) < 6) {
        echo json_encode(['status'=>'error','message'=>'新密码长度至少6位'],JSON_UNESCAPED_UNICODE); exit;
    }

    // 验证旧密码
    $hash = trim(@file_get_contents($pwdFile));
    if (empty($hash)) {
        echo json_encode(['status'=>'error','message'=>'密码文件不存在，请检查权限'],JSON_UNESCAPED_UNICODE); exit;
    }

    list($algo, $salt, $hashed) = explode(':', $hash . '::');
    $calc = hash('sha256', $old . $salt);
    if (strtolower($calc) !== strtolower($hashed)) {
        echo json_encode(['status'=>'error','message'=>'旧密码错误'],JSON_UNESCAPED_UNICODE); exit;
    }

    // 生成新密码哈希
    $salt = bin2hex(random_bytes(8));
    $newHash = 'sha256:' . $salt . ':' . hash('sha256', $new . $salt);
    if (safeWriteFile($pwdFile, $newHash)) {
        echo json_encode(['status'=>'success','message'=>'密码修改成功，请重新登录'],JSON_UNESCAPED_UNICODE);
    } else {
        echo json_encode(['status'=>'error','message'=>'密码写入失败，请检查权限'],JSON_UNESCAPED_UNICODE);
    }
    exit;
}

// ========================================================
// 未知路由
// ========================================================
echo json_encode(['status'=>'error','message'=>'未知操作'],JSON_UNESCAPED_UNICODE);
