<?php
header('Content-Type: application/json; charset=utf-8');

// 统一解析来自前端的 JSON Body、GET 与 POST 参数
$rawInput = file_get_contents('php://input');
$inputData = json_decode($rawInput, true) ?: [];

$action = $_GET['action'] ?? ($inputData['action'] ?? ($_POST['action'] ?? ''));

$ipFile     = '/etc/nginx/rules/ip_blacklist.conf';
$uaFile     = '/etc/nginx/rules/ua_blacklist.conf';
$tokenFile  = '/etc/nginx/rules/token_blacklist.conf';
$reloadFlag = '/etc/nginx/rules/.reload_flag';

// 智能获取 Nginx 配置文件路径（兼容 default.conf 或 default_4.conf）
function getNginxConfPath() {
    $confFiles = glob('/etc/nginx/conf.d/*.conf');
    return !empty($confFiles) ? $confFiles[0] : '/etc/nginx/conf.d/default.conf';
}

// 智能日志路径判断
$logFile = file_exists('/var/log/nginx/sub_access.log') 
    ? '/var/log/nginx/sub_access.log' 
    : '/var/log/nginx/access.log';

// ------------------- 辅助函数 -------------------

function safeWriteFile($filePath, $content, $append = false) {
    $dir = dirname($filePath);
    
    if (!is_dir($dir)) {
        @mkdir($dir, 0777, true);
        @chmod($dir, 0777);
    } else {
        @chmod($dir, 0777);
    }

    if (file_exists($filePath)) {
        @chmod($filePath, 0666);
    }

    $flags = $append ? FILE_APPEND : 0;
    $result = @file_put_contents($filePath, $content, $flags);

    if ($result !== false) {
        @chmod($filePath, 0666);
        return true;
    }

    return false;
}

function formatRule($type, $value) {
    switch ($type) {
        case 'ip':
            return "deny {$value};";
        case 'ua':
            $safeVal = preg_quote($value, '/');
            return "if (\$http_user_agent ~* \"{$safeVal}\") { return 403; }";
        case 'token':
            return "if (\$arg_token = \"{$value}\") { return 403; }";
        default:
            return '';
    }
}

function parseRuleValue($type, $line) {
    $line = trim($line);
    if (empty($line) || str_starts_with($line, '#')) return null;

    if ($type === 'ip' && preg_match('/^deny\s+([^;]+);/', $line, $m)) {
        return $m[1];
    }
    if ($type === 'ua' && preg_match('/if\s+\(\$http_user_agent\s+~*\s+"([^"]+)"\)/', $line, $m)) {
        return stripcslashes($m[1]);
    }
    if ($type === 'token' && preg_match('/if\s+\(\$arg_token\s+=\s+"([^"]+)"\)/', $line, $m)) {
        return $m[1];
    }
    return null;
}

function getSslCertificateInfo() {
    $certPath = '/etc/nginx/ssl/cert.pem';
    
    if (file_exists($certPath) && is_readable($certPath)) {
        $certContent = @file_get_contents($certPath);
        if ($certContent) {
            $certData = @openssl_x509_parse($certContent);
            if ($certData) {
                $validTo = $certData['validTo_time_t'] ?? 0;
                $daysLeft = ceil(($validTo - time()) / 86400);
                
                $domain = $certData['subject']['CN'] ?? '';
                if (isset($certData['extensions']['subjectAltName'])) {
                    $sans = explode(',', $certData['extensions']['subjectAltName']);
                    $cleanedSans = array_map(function($s) {
                        return trim(str_replace('DNS:', '', $s));
                    }, $sans);
                    if (!empty($cleanedSans)) {
                        $domain = implode(', ', $cleanedSans);
                    }
                }

                $issuer = $certData['issuer']['O'] ?? ($certData['issuer']['CN'] ?? 'Let\'s Encrypt');

                return [
                    'status' => 'success',
                    'cert' => [
                        'domain'    => $domain ?: '未知域名',
                        'issuer'    => $issuer,
                        'valid_to'  => date('Y-m-d H:i:s', $validTo),
                        'days_left' => max(0, (int)$daysLeft)
                    ]
                ];
            }
        }
    }

    $host = $_SERVER['HTTP_HOST'] ?? '';
    $domain = explode(':', $host)[0];
    if (!empty($domain) && $domain !== 'localhost' && !filter_var($domain, FILTER_VALIDATE_IP)) {
        $context = stream_context_create([
            "ssl" => [
                "capture_peer_cert" => true,
                "verify_peer"       => false,
                "verify_peer_name"  => false
            ]
        ]);
        $client = @stream_socket_client("ssl://{$domain}:443", $errno, $errstr, 3, STREAM_CLIENT_CONNECT, $context);
        if ($client) {
            $params = stream_context_get_params($client);
            fclose($client);
            if (isset($params["options"]["ssl"]["peer_certificate"])) {
                $certData = openssl_x509_parse($params["options"]["ssl"]["peer_certificate"]);
                $validTo  = $certData['validTo_time_t'] ?? 0;
                $daysLeft = ceil(($validTo - time()) / 86400);
                $issuer   = $certData['issuer']['O'] ?? ($certData['issuer']['CN'] ?? 'Let\'s Encrypt');

                return [
                    'status' => 'success',
                    'cert' => [
                        'domain'    => $certData['subject']['CN'] ?? $domain,
                        'issuer'    => $issuer,
                        'valid_to'  => date('Y-m-d H:i:s', $validTo),
                        'days_left' => max(0, (int)$daysLeft)
                    ]
                ];
            }
        }
    }

    $statusFile = '/etc/nginx/rules/cert_status.json';
    if (file_exists($statusFile)) {
        $json = json_decode(file_get_contents($statusFile), true);
        if (!empty($json)) {
            return [
                'status'  => 'processing',
                'message' => $json['msg'] ?? '证书申请中...'
            ];
        }
    }

    return [
        'status'  => 'error',
        'message' => '未检测到有效 SSL 证书文件或 443 端口未启用 SSL'
    ];
}

// ------------------- 路由处理 -------------------

// 1. 获取最新日志
if ($action === 'logs' || $action === 'get_logs') {
    $logs = [];
    if (file_exists($logFile)) {
        $cmd = "tail -n 300 " . escapeshellarg($logFile);
        exec($cmd, $lines);
        $lines = array_reverse($lines);

        $pattern = '/^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+)\s+([^\s"]*)[^"]*" (\d+) \d+ "([^"]*)" "([^"]*)"/';

        foreach ($lines as $line) {
            if (preg_match($pattern, $line, $m)) {
                $rawIp   = $m[1];
                $time    = $m[2];
                $method  = $m[3];
                $url     = $m[4];
                $status  = $m[5];
                $referer = ($m[6] === '-') ? '' : $m[6];
                $ua      = ($m[7] === '-') ? '' : $m[7];

                $token = '';
                $parsedUrl = parse_url($url);
                if (isset($parsedUrl['query'])) {
                    parse_str($parsedUrl['query'], $queryParams);
                    $token = $queryParams['token'] ?? '';
                }

                $logs[] = [
                    'ip'      => $rawIp,
                    'time'    => $time,
                    'method'  => $method,
                    'path'    => $parsedUrl['path'] ?? $url,
                    'url'     => $url,
                    'status'  => (int)$status,
                    'token'   => $token,
                    'ua'      => $ua,
                    'referer' => $referer
                ];
            }
        }
    }

    echo json_encode(['status' => 'success', 'data' => $logs]);
    exit;
}

// 2. 获取黑名单列表
if ($action === 'list') {
    $getRules = function($filePath, $type) {
        if (!file_exists($filePath)) return [];
        $lines = file($filePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $rules = [];
        foreach ($lines as $line) {
            $val = parseRuleValue($type, $line);
            if ($val !== null) $rules[] = $val;
        }
        return array_values(array_unique($rules));
    };

    echo json_encode([
        'status' => 'success',
        'data' => [
            'ip'    => $getRules($ipFile, 'ip'),
            'ua'    => $getRules($uaFile, 'ua'),
            'token' => $getRules($tokenFile, 'token')
        ]
    ]);
    exit;
}

// 3. 执行封禁
if ($action === 'ban') {
    $type  = $inputData['type'] ?? ($_POST['type'] ?? '');
    $value = trim($inputData['value'] ?? ($_POST['value'] ?? ''));

    if (!in_array($type, ['ip', 'ua', 'token']) || empty($value)) {
        echo json_encode(['status' => 'error', 'message' => '参数不合法']);
        exit;
    }

    $targetFile = match($type) {
        'ip'    => $ipFile,
        'ua'    => $uaFile,
        'token' => $tokenFile
    };

    $ruleLine = formatRule($type, $value);
    $existing = file_exists($targetFile) ? file_get_contents($targetFile) : '';

    if (!str_contains($existing, $ruleLine)) {
        if (!safeWriteFile($targetFile, $ruleLine . "\n", true)) {
            echo json_encode(['status' => 'error', 'message' => "无权限写入规则文件: {$targetFile}"]);
            exit;
        }
        safeWriteFile($reloadFlag, time());
    }

    echo json_encode(['status' => 'success', 'message' => "已成功封禁 {$type}: {$value}"]);
    exit;
}

// 4. 执行解封
if ($action === 'unban') {
    $type  = $inputData['type'] ?? ($_POST['type'] ?? '');
    $value = trim($inputData['value'] ?? ($_POST['value'] ?? ''));

    $targetFile = match($type) {
        'ip'    => $ipFile,
        'ua'    => $uaFile,
        'token' => $tokenFile,
        default => null
    };

    if (!$targetFile || !file_exists($targetFile)) {
        echo json_encode(['status' => 'error', 'message' => '找不到对应的规则文件']);
        exit;
    }

    $lines = file($targetFile, FILE_IGNORE_NEW_LINES);
    $newLines = [];
    foreach ($lines as $line) {
        $val = parseRuleValue($type, $line);
        if ($val !== null && $val === $value) {
            continue;
        }
        $newLines[] = $line;
    }

    if (!safeWriteFile($targetFile, implode("\n", $newLines) . "\n")) {
        echo json_encode(['status' => 'error', 'message' => "无权限更新文件: {$targetFile}"]);
        exit;
    }
    safeWriteFile($reloadFlag, time());

    echo json_encode(['status' => 'success', 'message' => '解封成功']);
    exit;
}

// 5. 实时查询 SSL 证书状态
if ($action === 'cert_status') {
    echo json_encode(getSslCertificateInfo());
    exit;
}

// 6. 获取面板绑定的 VPS 域名
if ($action === 'get_domain') {
    $confPath = getNginxConfPath();
    $domain = '';
    if (file_exists($confPath)) {
        $conf = file_get_contents($confPath);
        if (preg_match('/\bserver_name\s+([^;]+);/', $conf, $matches)) {
            $domain = trim($matches[1]);
        }
    }

    $certInfo = getSslCertificateInfo();

    echo json_encode([
        'domain'      => $domain,
        'cert_status' => $certInfo
    ]);
    exit;
}

// 7. 更新面板监听域名并触发证书申请
if ($action === 'update_domain' || $action === 'apply_cert') {
    $newDomain = trim($inputData['domain'] ?? ($_POST['domain'] ?? ''));
    if (empty($newDomain)) {
        echo json_encode(['status' => 'error', 'message' => '域名不能为空']);
        exit;
    }

    $confPath = getNginxConfPath();
    if (file_exists($confPath)) {
        $conf = file_get_contents($confPath);
        // 替换所有 server_name
        $newConf = preg_replace('/\bserver_name\s+[^;]+;/', "server_name {$newDomain};", $conf);
        
        if (!safeWriteFile($confPath, $newConf)) {
            echo json_encode([
                'status'  => 'error', 
                'message' => "权限不足！PHP 无法写入 Nginx 配置文件: {$confPath}"
            ]);
            exit;
        }
    }

    if (!safeWriteFile('/etc/nginx/rules/.cert_flag', $newDomain)) {
        echo json_encode([
            'status'  => 'error', 
            'message' => "权限不足！无法在 /etc/nginx/rules/ 目录创建标志文件。"
        ]);
        exit;
    }

    safeWriteFile('/etc/nginx/rules/cert_status.json', json_encode([
        'status' => 'processing',
        'msg'    => '已提交申请，后台正在联系 Let\'s Encrypt 签发证书...'
    ]));

    echo json_encode(['status' => 'success', 'message' => '配置已更新，正在后台自动申请证书...']);
    exit;
}

// 8. 获取当前反代的目标机场域名
if ($action === 'get_upstream') {
    $confPath = getNginxConfPath();
    $targetDomain = '';
    if (file_exists($confPath)) {
        $conf = file_get_contents($confPath);
        if (preg_match('/location\s+\/sub\/\s*\{[^}]*proxy_ssl_name\s+([^;]+);/s', $conf, $matches)) {
            $targetDomain = trim($matches[1]);
        } elseif (preg_match('/location\s+\/sub\/\s*\{[^}]*proxy_pass\s+https?:\/\/([^\/;\s]+)/s', $conf, $matches)) {
            $targetDomain = trim($matches[1]);
        }
    }
    echo json_encode(['status' => 'success', 'upstream' => $targetDomain]);
    exit;
}

// 9. 修改反代目标域名（更新机场域名）
if ($action === 'update_upstream') {
    $newTarget = trim($inputData['target_domain'] ?? ($_POST['target_domain'] ?? ''));
    if (empty($newTarget)) {
        echo json_encode(['status' => 'error', 'message' => '机场域名不能为空']);
        exit;
    }

    // 过滤 http://, https:// 前缀及末尾斜杠
    $newTarget = preg_replace('/^https?:\/\//i', '', $newTarget);
    $newTarget = rtrim($newTarget, '/');

    $confPath = getNginxConfPath();
    if (!file_exists($confPath)) {
        echo json_encode(['status' => 'error', 'message' => "找不到 Nginx 配置文件: {$confPath}"]);
        exit;
    }

    $conf = file_get_contents($confPath);

    // 精确匹配 location /sub/ { ... } 规则块
    if (preg_match('/(location\s+\/sub\/\s*\{)([\s\S]*?)(\})/i', $conf, $matches)) {
        $subBlock = $matches[2];

        // 1. 替换 proxy_pass
        if (preg_match('/proxy_pass\s+[^;]+;/', $subBlock)) {
            $subBlock = preg_replace('/proxy_pass\s+[^;]+;/', "proxy_pass https://{$newTarget};", $subBlock);
        } else {
            $subBlock .= "\n        proxy_pass https://{$newTarget};";
        }

        // 2. 替换 Host 请求头
        if (preg_match('/proxy_set_header\s+Host\s+[^;]+;/', $subBlock)) {
            $subBlock = preg_replace('/proxy_set_header\s+Host\s+[^;]+;/', "proxy_set_header Host {$newTarget};", $subBlock);
        } else {
            $subBlock .= "\n        proxy_set_header Host {$newTarget};";
        }

        // 3. 替换 proxy_ssl_name (正则排除 proxy_ssl_server_name)
        if (preg_match('/proxy_ssl_name\s+[^;]+;/', $subBlock)) {
            $subBlock = preg_replace('/proxy_ssl_name\s+[^;]+;/', "proxy_ssl_name {$newTarget};", $subBlock);
        } else {
            $subBlock .= "\n        proxy_ssl_name {$newTarget};";
        }

        // 4. 确保 proxy_ssl_server_name on; 存在
        if (!preg_match('/proxy_ssl_server_name\s+on;/', $subBlock)) {
            $subBlock .= "\n        proxy_ssl_server_name on;";
        }

        // 拼接回原配置文件
        $newConf = str_replace($matches[0], $matches[1] . $subBlock . "\n    " . $matches[3], $conf);

        if (!safeWriteFile($confPath, $newConf)) {
            echo json_encode(['status' => 'error', 'message' => "写入失败！请检查文件写权限"]);
            exit;
        }

        // 写入重载信号，通知后台 entrypoint.sh 触发 safe_nginx_reload
        safeWriteFile($reloadFlag, time());

        echo json_encode(['status' => 'success', 'message' => "已成功将反代目标替换为机场域名: {$newTarget}"]);
        exit;
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Nginx 配置中未查找到 location /sub/ 代理规则块']);
        exit;
    }
}

echo json_encode(['status' => 'error', 'message' => '无效的操作指令']);
