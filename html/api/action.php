<?php
// =====================================================
// SubMonitor - 统一管理接口
// =====================================================
if (headers_sent()) {
    http_response_code(500);
    exit('error: output before header');
}

session_start();
header('Content-Type: application/json; charset=utf-8');

// 鉴权引入
$authPath = __DIR__ . '/auth.php';
if (!file_exists($authPath)) {
    http_response_code(500);
    echo json_encode(['status'=>'error','message'=>'缺少 auth.php 鉴权文件'], JSON_UNESCAPED_UNICODE);
    exit;
}
require_once $authPath;

if (!isset($_SESSION['is_logged_in']) || $_SESSION['is_logged_in'] !== true) {
    http_response_code(401);
    echo json_encode(['status'=>'error','code'=>401,'message'=>'请先登录'], JSON_UNESCAPED_UNICODE);
    exit;
}

// 路径配置（与 Docker 挂载完全对齐）
define('RULES_DIR',    '/etc/nginx/rules/');
define('NGINX_CONF',   '/etc/nginx/conf.d/default.conf');
define('SSL_DIR',      '/etc/nginx/ssl/');

$ipFile     = RULES_DIR . 'ip_blacklist.conf';
$uaFile     = RULES_DIR . 'ua_blacklist.conf';
$tokenFile  = RULES_DIR . 'token_blacklist.conf';
$reloadFlag = RULES_DIR . '.reload_flag';
$logFile    = RULES_DIR . 'access.log';

foreach ([RULES_DIR, SSL_DIR, dirname(NGINX_CONF)] as $dir) {
    if (!is_dir($dir)) @mkdir($dir, 0777, true);
    @chmod($dir, 0777);
}

// 参数解析
$rawInput  = file_get_contents('php://input');
$inputData = json_decode($rawInput, true) ?: [];
$action    = $_GET['action'] ?? $inputData['action'] ?? $_POST['action'] ?? '';

// 辅助函数
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

function formatRule(string $type, string $value): string
{
    switch ($type) {
        case 'ip': return "deny {$value};";
        case 'ua': $s=preg_quote($value,'/'); return "if (\$http_user_agent ~* \"{$s}\") { return 403; }";
        case 'token': return "if (\$arg_token = \"{$value}\") { return 403; }";
        default: return '';
    }
}

function parseRuleValue(string $type, string $line): ?string
{
    $line=trim($line);
    if (empty($line) || str_starts_with($line,'#')) return null;
    if ($type==='ip' && preg_match('/^deny\s+([^;]+);/',$line,$m)) return $m[1];
    if ($type==='ua' && preg_match('/if\s+\(\$http_user_agent\s+~*\s+"([^"]+)"\)/',$line,$m)) return stripcslashes($m[1]);
    if ($type==='token' && preg_match('/if\s+\(\$arg_token\s+=\s+"([^"]+)"\)/',$line,$m)) return $m[1];
    return null;
}

function getSslCertificateInfo(): array
{
    $certPath=SSL_DIR.'cert.pem';
    if (file_exists($certPath) && is_readable($certPath)) {
        $cert=@file_get_contents($certPath);
        if ($cert && function_exists('openssl_x509_parse')) {
            $d=@openssl_x509_parse($cert);
            if ($d) {
                $t=$d['validTo_time_t']??0;
                $days=ceil(($t-time())/86400);
                $dom=$d['subject']['CN']??'';
                if (!empty($d['extensions']['subjectAltName'])) {
                    $sans=explode(',',$d['extensions']['subjectAltName']);
                    $sans=array_map(fn($s)=>trim(str_replace('DNS:','',$s)),$sans);
                    $dom=implode(', ',$sans);
                }
                $iss=$d['issuer']['O']??$d['issuer']['CN']??'Let\'s Encrypt';
                return ['status'=>'success','cert'=>['domain'=>$dom?:'未知域名','issuer'=>$iss,'valid_to'=>date('Y-m-d H:i:s',$t),'days_left'=>max(0,(int)$days)]];
            }
        }
    }
    $sf=RULES_DIR.'cert_status.json';
    if (file_exists($sf)) {
        $j=json_decode(file_get_contents($sf),true);
        if (!empty($j)) return ['status'=>'processing','message'=>$j['msg']??'证书申请中...'];
    }
    return ['status'=>'error','message'=>'未检测到有效SSL证书'];
}

// 路由：获取日志
if ($action==='logs' || $action==='get_logs') {
    $logs=[];
    if (file_exists($logFile)) {
        $lines=file($logFile,FILE_IGNORE_NEW_LINES|FILE_SKIP_EMPTY_LINES)?:[];
        $lines=array_slice($lines,-300);
        $lines=array_reverse($lines);
        $p='/^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+)\s+([^\s"]*)[^"]*" (\d+)/';
        foreach ($lines as $ln) {
            if (preg_match($p,$ln,$m)) {
                $logs[]=['ip'=>$m[1]??'-','time'=>$m[2]??'-','method'=>$m[3]??'-','path'=>parse_url($m[4]??'/',PHP_URL_PATH)?:'/','url'=>$m[4]??'-','status'=>(int)($m[5]??0),'token'=>'','ua'=>'-','referer'=>'-'];
            }
        }
    }
    echo json_encode(['status'=>'success','data'=>$logs],JSON_UNESCAPED_UNICODE);
    exit;
}

// 路由：获取黑名单
if ($action==='list') {
    $f=fn($fp,$t)=>file_exists($fp)?array_values(array_filter(array_map(fn($ln)=>parseRuleValue($t,$ln),file($fp,FILE_IGNORE_NEW_LINES|FILE_SKIP_EMPTY_LINES)))):[];
    echo json_encode(['status'=>'success','data'=>['ip'=>$f($ipFile,'ip'),'ua'=>$f($uaFile,'ua'),'token'=>$f($tokenFile,'token')]],JSON_UNESCAPED_UNICODE);
    exit;
}

// 路由：封禁
if ($action==='ban') {
    $type=$inputData['type']??$_POST['type']??'';
    $val=trim($inputData['value']??$_POST['value']??'');
    if (!in_array($type,['ip','ua','token'],true) || empty($val)) {
        echo json_encode(['status'=>'error','message'=>'参数不合法'],JSON_UNESCAPED_UNICODE); exit;
    }
    $tf=match($type){'ip'=>$ipFile,'ua'=>$uaFile,'token'=>$tokenFile};
    $rule=formatRule($type,$val);
    if (!str_contains(@file_get_contents($tf)?:'',$rule)) {
        if (!safeWriteFile($tf,$rule."\n",true)) {
            echo json_encode(['status'=>'error','message'=>'写入失败，请检查挂载权限'],JSON_UNESCAPED_UNICODE); exit;
        }
        safeWriteFile($reloadFlag,(string)time());
    }
    echo json_encode(['status'=>'success','message'=>"已封禁：{$type} → {$val}"],JSON_UNESCAPED_UNICODE); exit;
}

// 路由：解封
if ($action==='unban') {
    $type=$inputData['type']??$_POST['type']??'';
    $val=trim($inputData['value']??$_POST['value']??'');
    $tf=match($type){'ip'=>$ipFile,'ua'=>$uaFile,'token'=>$tokenFile,default=>null};
    if (!$tf||!file_exists($tf)) { echo json_encode(['status'=>'error','message'=>'规则文件不存在'],JSON_UNESCAPED_UNICODE); exit; }
    $lines=file($tf,FILE_IGNORE_NEW_LINES)?:[]; $new=[];
    foreach ($lines as $ln) { $v=parseRuleValue($type,$ln); if ($v!==null&&$v===$val) continue; $new[]=$ln; }
    if (!safeWriteFile($tf,implode("\n",$new)."\n")) { echo json_encode(['status'=>'error','message'=>'更新文件失败'],JSON_UNESCAPED_UNICODE); exit; }
    safeWriteFile($reloadFlag,(string)time());
    echo json_encode(['status'=>'success','message'=>'解封成功'],JSON_UNESCAPED_UNICODE); exit;
}

// 路由：证书状态
if ($action==='cert_status') { echo json_encode(getSslCertificateInfo(),JSON_UNESCAPED_UNICODE); exit; }

// 路由：获取反代域名
if ($action==='get_upstream') {
    $u='';
    if (file_exists(NGINX_CONF) && preg_match('/proxy_pass\s+https?:\/\/([^\/;\s]+)/i',file_get_contents(NGINX_CONF),$m)) $u=trim($m[1]);
    echo json_encode(['status'=>'success','upstream'=>$u],JSON_UNESCAPED_UNICODE); exit;
}

// 路由：修改反代域名
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
    safeWriteFile($reloadFlag,(string)time());
    echo json_encode(['status'=>'success','message'=>"反代域名已更新：{$t}"],JSON_UNESCAPED_UNICODE); exit;
}

// 路由：申请证书/更新域名
if ($action==='apply_cert' || $action==='update_domain') {
    $d=trim($inputData['domain']??$_POST['domain']??'');
    if (empty($d)) { echo json_encode(['status'=>'error','message'=>'域名不能为空'],JSON_UNESCAPED_UNICODE); exit; }
    safeWriteFile(RULES_DIR.'.cert_flag',"{$d}\n");
    safeWriteFile(RULES_DIR.'cert_status.json',json_encode(['status'=>'processing','msg'=>"域名 {$d} 已提交，后台正在申请证书..."]));
    echo json_encode(['status'=>'success','message'=>"域名 {$d} 已保存，证书申请已在后台启动"],JSON_UNESCAPED_UNICODE); exit;
}

echo json_encode(['status'=>'error','message'=>'无效的操作指令'],JSON_UNESCAPED_UNICODE);
