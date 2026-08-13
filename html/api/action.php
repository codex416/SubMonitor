<?php
require_once __DIR__ . '/auth.php';

// 统一用容器内标准路径，确保100%能找到文件！[cite: 8]
define('RULES_DIR',    '/opt/SubMonitor/rules/');
define('NGINX_CONF',   '/etc/nginx/conf.d/default.conf');
define('SSL_DIR',      '/etc/nginx/ssl/');
define('LOGIN_PHP',    __DIR__ . '/login.php'); 
define('ADMIN_PASSWORD_FILE', __DIR__ . '/../.admin_password');
// 定义管理员路径存储文件
define('ADMIN_PATH_FILE', __DIR__ . '/../.admin_path');

header('Content-Type: application/json; charset=utf-8');
require_login();

// 强制设置时区为北京时间 (UTC+8)，确保获取到的证书到期时间准确[cite: 8]
date_default_timezone_set('Asia/Shanghai');

$inputData = json_decode(file_get_contents('php://input'), true) ?? [];
$action = trim($inputData['action'] ?? $_POST['action'] ?? $_GET['action'] ?? '');
$reloadFlag = RULES_DIR . '.reload_flag';

// ── 调试日志：记录每一次请求的动作和原始数据，方便排查 ──[cite: 8]
@error_log("DEBUG_REQUEST: Method=" . $_SERVER['REQUEST_METHOD'] . " | Action=" . $action . " | RAW=" . file_get_contents('php://input'));

// 强制确保所有目录存在+可写[cite: 8]
foreach ([RULES_DIR, SSL_DIR, dirname(NGINX_CONF), dirname(LOGIN_PHP), dirname(ADMIN_PASSWORD_FILE), dirname(ADMIN_PATH_FILE)] as $dir) {
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
// ✅ 1. 更新反代目标域名（使用按行精准定位替换，100%生效）[cite: 8]
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

    // 逐行读取并精准替换 backend_url 这一行[cite: 8]
    $lines = file(NGINX_CONF);
    $newLines = [];
    $updated = false;
    foreach ($lines as $line) {
        if (strpos($line, '$backend_url') !== false && strpos($line, 'set') !== false) {
            $newLines[] = "        set \$backend_url \"https://{$t}\";\n";
            $updated = true;
        } else {
            $newLines[] = $line;
        }
    }
    
    $c = implode('', $newLines);

    safeWriteFile(RULES_DIR . 'upstream.conf', $t);

    if (!safeWriteFile(NGINX_CONF, $c)) {
        echo json_encode(['status'=>'error','message'=>'写入配置失败，请检查权限'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    @file_put_contents($reloadFlag, (string)time());

    echo json_encode(['status'=>'success','message'=>"✅ 反代域名已更新为：{$t}，配置已触发自动重载"], JSON_UNESCAPED_UNICODE);
    exit;
}

// ========================================================
// ✅ 1.1 获取当前反代目标域名[cite: 8]
// ========================================================
if ($action === 'get_upstream') {
    $upstream = '';
    if (file_exists(RULES_DIR . 'upstream.conf')) {
        $upstream = trim(file_get_contents(RULES_DIR . 'upstream.conf'));
    } elseif (file_exists(NGINX_CONF)) {
        $confContent = file_get_contents(NGINX_CONF);
        if (preg_match('/set\s+\$backend_url\s+"https?:\/\/([^"]+)";/i', $confContent, $m)) {
            $upstream = trim($m[1]);
        } elseif (preg_match('/proxy_pass\s+https?:\/\/([^\/;\s]+)/i', $confContent, $m)) {
            $upstream = trim($m[1]);
        }
    }
    echo json_encode(['status' => 'success', 'upstream' => $upstream], JSON_UNESCAPED_UNICODE);
    exit;
}

// ========================================================
// ✅ 2. 更新域名 + 申请证书[cite: 8]
// ========================================================
if ($action === 'apply_cert' || $action === 'update_domain') {
    $d = trim($inputData['domain'] ?? $_POST['domain'] ?? '');
    if (empty($d)) {
        echo json_encode(['status'=>'error','message'=>'域名不能为空'], JSON_UNESCAPED_UNICODE);
        exit;
    }
    safeWriteFile(RULES_DIR.'domain.conf', $d);
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
// ✅ 3. 获取证书状态[cite: 8]
// ========================================================
if ($action === 'cert_status') {
    $certPath = SSL_DIR.'cert.pem';
    
    if (file_exists($certPath)) {
        $pem = @file_get_contents($certPath);
        if ($pem && preg_match_all('/-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----/s', $pem, $m)) {
            $leaf = $m[0][0] ?? '';
            $certData = openssl_x509_parse($leaf);
            
            if ($certData) {
                $validToTime = $certData['validTo_time_t'] ?? time();
                $valid_to = date('Y-m-d H:i:s', $validToTime);
                $daysLeft = ceil(($validToTime - time()) / 86400);
                
                // 🛠️ 修复点：对颁发机构进行名称映射，将 YR1 规范显示为 Let's Encrypt[cite: 8]
                $rawIssuer = $certData['issuer']['CN'] ?? ($certData['issuer']['organizationName'] ?? 'Let\'s Encrypt');
                if (strpos($rawIssuer, 'YR') !== false || strpos($rawIssuer, 'Let\'s Encrypt') !== false) {
                    $issuer = 'Let\'s Encrypt';
                } else {
                    $issuer = $rawIssuer;
                }
                
                $domain = $certData['subject']['CN'] ?? '';
                if (empty($domain) && file_exists(RULES_DIR.'domain.conf')) {
                    $domain = trim(file_get_contents(RULES_DIR.'domain.conf'));
                }
                if (empty($domain)) {
                    $domain = 'example.com';
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
// ✅ 4. 更新黑名单（兼容所有常见命名，并格式化为标准 Nginx 语法）[cite: 8]
// ========================================================
if ($action === 'update_blacklist' || $action === 'blacklist' || $action === 'save_blacklist') {
    $ipList = $inputData['ip_blacklist'] ?? $_POST['ip_blacklist'] ?? [];
    $uaList = $inputData['ua_blacklist'] ?? $_POST['ua_blacklist'] ?? [];
    $tokenList = $inputData['token_blacklist'] ?? $_POST['token_blacklist'] ?? [];

    $ipLines = [];
    foreach (array_filter(array_map('trim', $ipList)) as $ip) {
        if (strpos($ip, '#') === 0) continue;
        $clean = str_ireplace(['deny ', ';'], '', $ip);
        if (!empty($clean)) {
            $ipLines[] = "deny {$clean};";
        }
    }
    $ipContent = '# 禁止访问的 IP'."\n" . implode("\n", $ipLines) . "\n";

    $uaLines = [];
    foreach (array_filter(array_map('trim', $uaList)) as $ua) {
        if (strpos($ua, '#') === 0) continue;
        $clean = addslashes($ua);
        if (!empty($clean)) {
            $uaLines[] = "if (\$http_user_agent ~* \"{$clean}\") { return 403; }";
        }
    }
    $uaContent = '# 禁止访问的 UA'."\n" . implode("\n", $uaLines) . "\n";

    $tokenLines = [];
    foreach (array_filter(array_map('trim', $tokenList)) as $token) {
        if (strpos($token, '#') === 0) continue;
        $clean = addslashes($token);
        if (!empty($clean)) {
            $tokenLines[] = "if (\$arg_token = \"{$clean}\") { return 403; }";
        }
    }
    $tokenContent = '# 禁止访问的 Token'."\n" . implode("\n", $tokenLines) . "\n";

    $ok1 = safeWriteFile(RULES_DIR.'ip_blacklist.conf', $ipContent);
    $ok2 = safeWriteFile(RULES_DIR.'ua_blacklist.conf', $uaContent);
    $ok3 = safeWriteFile(RULES_DIR.'token_blacklist.conf', $tokenContent);

    @file_put_contents($reloadFlag, (string)time());

    if ($ok1 && $ok2 && $ok3) {
        echo json_encode(['status'=>'success','message'=>'✅ 黑名单已更新，配置已生效'], JSON_UNESCAPED_UNICODE);
    } else {
        echo json_encode(['status'=>'error','message'=>'⚠️ 部分文件写入失败'], JSON_UNESCAPED_UNICODE);
    }
    exit;
}

// ========================================================
// ✅ 4.1 处理快捷封禁动作 (来自日志页面的快捷封禁，动作名为 ban)[cite: 8]
// ========================================================
if ($action === 'ban') {
    $type = trim($inputData['type'] ?? '');
    $value = trim($inputData['value'] ?? '');

    if (empty($type) || empty($value)) {
        echo json_encode(['status'=>'error','message'=>'封禁类型或值不能为空'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $fileMap = [
        'ip' => RULES_DIR . 'ip_blacklist.conf',
        'ua' => RULES_DIR . 'ua_blacklist.conf',
        'token' => RULES_DIR . 'token_blacklist.conf'
    ];

    if (!isset($fileMap[$type])) {
        echo json_encode(['status'=>'error','message'=>'非法的封禁类型'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $targetFile = $fileMap[$type];
    
    $currentContent = file_exists($targetFile) ? file_get_contents($targetFile) : '';
    $lines = array_filter(array_map('trim', explode("\n", $currentContent)));
    $lines = array_filter($lines, function($l) { return strpos($l, '#') !== 0; });

    $formattedValue = $value;
    if ($type === 'ip') {
        $clean = str_ireplace(['deny ', ';'], '', $value);
        $formattedValue = "deny {$clean};";
    } elseif ($type === 'ua') {
        $clean = addslashes($value);
        $formattedValue = "if (\$http_user_agent ~* \"{$clean}\") { return 403; }";
    } elseif ($type === 'token') {
        $clean = addslashes($value);
        $formattedValue = "if (\$arg_token = \"{$clean}\") { return 403; }";
    }

    $exists = false;
    foreach ($lines as $line) {
        if ($line === $formattedValue) {
            $exists = true;
            break;
        }
    }

    if (!$exists) {
        $lines[] = $formattedValue;
    }

    $newContent = '# 禁止访问的 ' . strtoupper($type) . "\n" . implode("\n", $lines) . "\n";
    $ok = safeWriteFile($targetFile, $newContent);

    @file_put_contents($reloadFlag, (string)time());

    if ($ok) {
        echo json_encode(['status'=>'success','message'=>"✅ 成功将 [{$value}] 加入 {$type} 黑名单"], JSON_UNESCAPED_UNICODE);
    } else {
        echo json_encode(['status'=>'error','message'=>'⚠️ 写入黑名单文件失败'], JSON_UNESCAPED_UNICODE);
    }
    exit;
}

// ========================================================
// ✅ 4.1.2 处理快捷解封动作 (动作名为 unban 或 remove_blacklist)[cite: 8]
// ========================================================
if ($action === 'unban' || $action === 'remove_blacklist') {
    $type = trim($inputData['type'] ?? '');
    $value = trim($inputData['value'] ?? '');

    if (empty($type) || empty($value)) {
        echo json_encode(['status'=>'error','message'=>'解封类型或值不能为空'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $fileMap = [
        'ip' => RULES_DIR . 'ip_blacklist.conf',
        'ua' => RULES_DIR . 'ua_blacklist.conf',
        'token' => RULES_DIR . 'token_blacklist.conf'
    ];

    if (!isset($fileMap[$type])) {
        echo json_encode(['status'=>'error','message'=>'非法的解封类型'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $targetFile = $fileMap[$type];
    if (!file_exists($targetFile)) {
        echo json_encode(['status'=>'success','message'=>"✅ 该黑名单文件为空"], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $currentContent = file_get_contents($targetFile);
    $lines = explode("\n", $currentContent);
    $newLines = [];

    foreach ($lines as $line) {
        $trimmed = trim($line);
        if (empty($trimmed) || strpos($trimmed, '#') === 0) {
            $newLines[] = $line;
            continue;
        }

        $matchFound = false;
        if ($type === 'ip') {
            $cleanVal = str_ireplace(['deny ', ';'], '', $value);
            if ($trimmed === "deny {$cleanVal};" || strpos($trimmed, $cleanVal) !== false) {
                $matchFound = true;
            }
        } elseif ($type === 'ua') {
            $cleanVal = addslashes($value);
            if ($trimmed === "if (\$http_user_agent ~* \"{$cleanVal}\") { return 403; }" || strpos($trimmed, $cleanVal) !== false) {
                $matchFound = true;
            }
        } elseif ($type === 'token') {
            $cleanVal = addslashes($value);
            if ($trimmed === "if (\$arg_token = \"{$cleanVal}\") { return 403; }" || strpos($trimmed, $cleanVal) !== false) {
                $matchFound = true;
            }
        }

        if (!$matchFound) {
            $newLines[] = $line;
        }
    }

    $newContent = implode("\n", $newLines);
    $ok = safeWriteFile($targetFile, $newContent);

    @file_put_contents($reloadFlag, (string)time());

    if ($ok) {
        echo json_encode(['status'=>'success','message'=>"✅ 成功将 [{$value}] 从 {$type} 黑名单中解封"], JSON_UNESCAPED_UNICODE);
    } else {
        echo json_encode(['status'=>'error','message'=>'⚠️ 写入黑名单文件失败'], JSON_UNESCAPED_UNICODE);
    }
    exit;
}

// ========================================================
// ✅ 4.2 补丁：获取黑名单完整列表 (对应前端 fetchBlacklistRules)[cite: 8]
// ========================================================
if ($action === 'list') {
    $parseIpList = function($filePath) {
        if (!file_exists($filePath)) return [];
        $lines = explode("\n", file_get_contents($filePath));
        $res = [];
        foreach ($lines as $l) {
            $l = trim($l);
            if (empty($l) || strpos($l, '#') === 0) continue;
            $l = preg_replace('/^deny\s+/i', '', $l);
            $l = rtrim($l, ';');
            $res[] = trim($l, '"');
        }
        return array_filter($res);
    };

    $parseUaTokenList = function($filePath) {
        if (!file_exists($filePath)) return [];
        $lines = explode("\n", file_get_contents($filePath));
        $res = [];
        foreach ($lines as $l) {
            $l = trim($l);
            if (empty($l) || strpos($l, '#') === 0) continue;
            if (preg_match('/~*\s*"([^"]+)"/', $l, $m)) {
                $res[] = stripslashes($m[1]);
            } elseif (preg_match('/=\s*"([^"]+)"/', $l, $m)) {
                $res[] = stripslashes($m[1]);
            } else {
                $res[] = ltrim(trim($l), '# ');
            }
        }
        return array_filter($res);
    };

    echo json_encode([
        'status' => 'success',
        'code'   => 200,
        'data'   => [
            'ip'    => $parseIpList(RULES_DIR.'ip_blacklist.conf'),
            'ua'    => $parseUaTokenList(RULES_DIR.'ua_blacklist.conf'),
            'token' => $parseUaTokenList(RULES_DIR.'token_blacklist.conf'),
        ]
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

// ========================================================
// ✅ 5. 读取配置[cite: 8]
// ========================================================
if ($action === 'get_config') {
    $domain = '';
    if (file_exists(NGINX_CONF)) {
        $confContent = file_get_contents(NGINX_CONF);
        if (preg_match('/set\s+\$backend_url\s+"https?:\/\/([^"]+)";/i', $confContent, $m)) {
            $domain = trim($m[1]);
        } elseif (preg_match('/proxy_pass\s+https?:\/\/([^\/;\s]+)/i', $confContent, $m)) {
            $domain = trim($m[1]);
        }
    }

    $parseIpList = function($filePath) {
        if (!file_exists($filePath)) return [];
        $lines = explode("\n", file_get_contents($filePath));
        $res = [];
        foreach ($lines as $l) {
            $l = trim($l);
            if (empty($l) || strpos($l, '#') === 0) continue;
            $l = preg_replace('/^deny\s+/i', '', $l);
            $l = rtrim($l, ';');
            $res[] = trim($l, '"');
        }
        return array_filter($res);
    };

    $parseUaTokenList = function($filePath) {
        if (!file_exists($filePath)) return [];
        $lines = explode("\n", file_get_contents($filePath));
        $res = [];
        foreach ($lines as $l) {
            $l = trim($l);
            if (empty($l) || strpos($l, '#') === 0) continue;
            if (preg_match('/~*\s*"([^"]+)"/', $l, $m)) {
                $res[] = stripslashes($m[1]);
            } elseif (preg_match('/=\s*"([^"]+)"/', $l, $m)) {
                $res[] = stripslashes($m[1]);
            } else {
                $res[] = ltrim(trim($l), '# ');
            }
        }
        return array_filter($res);
    };

    // 读取当前配置的管理员路径（默认 /abd12we）
    $adminPath = file_exists(ADMIN_PATH_FILE) ? trim(file_get_contents(ADMIN_PATH_FILE)) : '/abd12we';

    echo json_encode([
        'status'=>'success',
        'config'=>[
            'target_domain'=>$domain,
            'admin_path'=>$adminPath,
            'ip_blacklist'=>$parseIpList(RULES_DIR.'ip_blacklist.conf'),
            'ua_blacklist'=>$parseUaTokenList(RULES_DIR.'ua_blacklist.conf'),
            'token_blacklist'=>$parseUaTokenList(RULES_DIR.'token_blacklist.conf'),
        ]
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

// ========================================================
// ✅ 6. 修改密码[cite: 8]
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
// ✅ 7. 修改管理员路径
// ========================================================
if ($action === 'change_admin_path') {
    $newPath = trim($inputData['admin_path'] ?? $_POST['admin_path'] ?? '');
    
    if (empty($newPath)) {
        echo json_encode(['status'=>'error','message'=>'路径不能为空'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    // 格式化路径，确保以 / 开头，且没有尾随斜杠
    if ($newPath[0] !== '/') {
        $newPath = '/' . $newPath;
    }
    $newPath = rtrim($newPath, '/');

    // 基础安全和合法性校验（只允许字母、数字、下划线、中划线及斜杠）
    if (!preg_match('/^\/[a-zA-Z0-9_\-\/]+$/', $newPath)) {
        echo json_encode(['status'=>'error','message'=>'路径格式不合法，仅支持字母、数字、下划线和中划线'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    if (safeWriteFile(ADMIN_PATH_FILE, $newPath)) {
        @chmod(ADMIN_PATH_FILE, 0600);
        echo json_encode(['status'=>'success','message'=>"✅ 管理路径修改成功！新路径为：{$newPath}"], JSON_UNESCAPED_UNICODE);
    } else {
        echo json_encode(['status'=>'error','message'=>'❌ 写入失败：请检查目录权限'], JSON_UNESCAPED_UNICODE);
    }
    exit;
}

// ========================================================
echo json_encode(['status'=>'error','message'=>"⚠️ 未知操作：[{$action}]"], JSON_UNESCAPED_UNICODE);
