<?php
header('Content-Type: application/json; charset=utf-8');

$logFile = '/var/log/nginx/sub_access.log';
$cacheFile = __DIR__ . '/ip_cache.json';

// 加载 IP 缓存
$ipCache = [];
if (file_exists($cacheFile)) {
    $ipCache = json_decode(file_get_contents($cacheFile), true) ?: [];
}

// IP 地理位置查询（含超限处理与快速回退）
function getIpLocation($ip, &$ipCache, $cacheFile) {
    if (isset($ipCache[$ip])) {
        return $ipCache[$ip];
    }

    if ($ip === '127.0.0.1' || $ip === 'localhost' || strpos($ip, '192.168.') === 0 || strpos($ip, '10.') === 0) {
        $ipCache[$ip] = '局域网 / 本地访问';
        file_put_contents($cacheFile, json_encode($ipCache, JSON_UNESCAPED_UNICODE));
        return $ipCache[$ip];
    }

    $ctx = stream_context_create([
        'http' => [
            'timeout' => 1,
            'header'  => "User-Agent: Mozilla/5.0\r\n"
        ]
    ]);

    $json = @file_get_contents("http://ip-api.com/json/{$ip}?lang=zh-CN", false, $ctx);
    if ($json) {
        $data = json_decode($json, true);
        if ($data && isset($data['status']) && $data['status'] === 'success') {
            $location = ($data['country'] ?? '') . ' ' . ($data['regionName'] ?? '') . ' ' . ($data['city'] ?? '');
            $location = trim($location) ?: '未知网络';
            $ipCache[$ip] = $location;
            file_put_contents($cacheFile, json_encode($ipCache, JSON_UNESCAPED_UNICODE));
            return $location;
        }
    }

    // 规避频率限制，失败时临时记录为未知，避免卡顿
    return '未知（查询受限）';
}

if (!file_exists($logFile)) {
    echo json_encode(['status' => 'success', 'data' => [], 'summary' => ['total' => 0, 'unique_ips' => 0]]);
    exit;
}

$lines = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
$logs = [];
$uniqueIps = [];

// 倒序读取最近的日志记录
$lines = array_reverse($lines);
$maxLines = 500;
$count = 0;

foreach ($lines as $line) {
    if ($count >= $maxLines) break;

    // 兼容 HTTP/1.1、HTTP/2 及各种请求方法的日志正则
    if (preg_match('/^(\S+) \S+ \S+ \[(.*?)\] "(\S+)\s+(\S+)\s+HTTP\/[^"]+" (\d{3}) \d+ "([^"]*)" "([^"]*)"/', $line, $matches)) {
        $ip       = $matches[1];
        $timeRaw  = $matches[2];
        $method   = $matches[3];
        $url      = $matches[4];
        $status   = $matches[5];
        $referer  = $matches[6];
        $ua       = $matches[7];

        $uniqueIps[$ip] = true;
        $location = getIpLocation($ip, $ipCache, $cacheFile);

        $logs[] = [
            'ip'       => $ip,
            'location' => $location,
            'time'     => $timeRaw,
            'method'   => $method,
            'url'      => $url,
            'status'   => $status,
            'ua'       => $ua
        ];
        $count++;
    }
}

echo json_encode([
    'status' => 'success',
    'summary' => [
        'total'      => count($lines),
        'unique_ips' => count($uniqueIps)
    ],
    'data' => $logs
], JSON_UNESCAPED_UNICODE);
