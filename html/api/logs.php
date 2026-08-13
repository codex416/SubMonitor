<?php
require_once __DIR__ . '/auth.php';
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');

date_default_timezone_set('Asia/Shanghai');

$logFile = '/etc/nginx/rules/access.log';
$cacheFile = '/tmp/ip_cache.json';

if (!file_exists($logFile)) {
    echo json_encode([]);
    exit;
}

$ipCache = [];
if (file_exists($cacheFile)) {
    $ipCache = json_decode(file_get_contents($cacheFile), true) ?: [];
}
$cacheUpdated = false;

function getIpLocation($ip, &$ipCache, &$cacheUpdated) {
    if (!$ip || $ip === '-') return '未知';
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        return "局域网 IP";
    }
    if (isset($ipCache[$ip])) {
        return $ipCache[$ip];
    }
    $ctx = stream_context_create([
        'http' => ['timeout' => 1, 'header' => "User-Agent: Mozilla/5.0\r\n"]
    ]);
    $res = @file_get_contents("http://ip-api.com/json/{$ip}?lang=zh-CN", false, $ctx);
    if ($res) {
        $data = json_decode($res, true);
        if ($data && isset($data['status']) && $data['status'] === 'success') {
            $info = sprintf("%s %s %s %s", 
                $data['country'] ?? '', $data['regionName'] ?? '', 
                $data['city'] ?? '', $data['isp'] ?? '');
            $info = trim($info) ?: '公网 IP';
            $ipCache[$ip] = $info;
            $cacheUpdated = true;
            return $info;
        }
    }
    return "公网 IP";
}

$fp = fopen($logFile, 'r');
if (!$fp) { echo json_encode([]); exit; }
$size = filesize($logFile);
$readSize = min($size, 262144);
$lines = [];
if ($readSize > 0) {
    fseek($fp, $size - $readSize);
    $data = fread($fp, $readSize);
    fclose($fp);
    $lines = array_filter(explode("\n", $data));
} else {
    fclose($fp);
}
$lines = array_reverse($lines);
$result = [];
$targetTimeZone = new DateTimeZone('Asia/Shanghai');

foreach ($lines as $line) {
    if (preg_match('/^(\S+) \S+ \S+ \[(.*?)\] "(?:GET|POST|HEAD) (\S+) HTTP\/[^"]+" (\d{3}) \d+ "([^"]*)" "([^"]*)"/', $line, $matches)) {
        $ip = $matches[1];
        $timeRaw = $matches[2];
        $url = $matches[3];
        $status = $matches[4];
        $ua = $matches[6];

        $parsedUrl = parse_url($url);
        $path = $parsedUrl['path'] ?? $url;

        # 核心修复：放行证书和反代相关的 API 请求
        if ((strpos($url, '/api/') !== false && strpos($url, 'cert') === false && strpos($url, 'domain') === false) || $path === '/' || $path === '/index.html' || $path === '/login.html' || preg_match('/\.(js|css|ico|png|jpg|html|txt|woff)$/i', $path)) {
            continue;
        }

        $token = '-';
        $queryString = $parsedUrl['query'] ?? '';
        if ($queryString) {
            parse_str($queryString, $queryParams);
            if (!empty($queryParams['token'])) {
                $token = $queryParams['token'];
            }
        }
        if ($token === '-' && $path !== '/' && $path !== '') {
            $segments = explode('/', trim($path, '/'));
            foreach ($segments as $seg) {
                if (strpos($seg, '.') === false && strlen($seg) >= 8 && !in_array($seg, ['sub','api','static','admin','login'])) {
                    $token = $seg;
                    break;
                }
            }
        }

        $dt = DateTime::createFromFormat('d/M/Y:H:i:s O', $timeRaw);
        $formattedTime = $dt ? $dt->setTimezone($targetTimeZone)->format('Y-m-d H:i:s') : $timeRaw;

        $result[] = [
            'time'    => $formattedTime,
            'ip'      => $ip,
            'ip_info' => getIpLocation($ip, $ipCache, $cacheUpdated),
            'token'   => $token,
            'status'  => $status,
            'ua'      => $ua
        ];

        if (count($result) >= 100) break;
    }
}

if ($cacheUpdated) {
    @file_put_contents($cacheFile, json_encode($ipCache, JSON_UNESCAPED_UNICODE));
}

echo json_encode($result, JSON_UNESCAPED_UNICODE);
exit;
