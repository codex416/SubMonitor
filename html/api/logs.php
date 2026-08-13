<?php
require_once __DIR__ . '/auth.php';
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');

date_default_timezone_set('Asia/Shanghai');

$logFile = '/opt/SubMonitor/rules/access.log';

if (!file_exists($logFile)) {
    echo json_encode([]);
    exit;
}

$fp = fopen($logFile, 'r');
if (!$fp) { 
    echo json_encode([]); 
    exit; 
}

$lines = [];
// 【优化 1】加上文件共享锁，确保高并发写入时读取安全
if (flock($fp, LOCK_SH)) {
    $size = filesize($logFile);
    $readSize = min($size, 262144);
    if ($readSize > 0) {
        fseek($fp, $size - $readSize);
        $data = fread($fp, $readSize);
        $lines = array_filter(explode("\n", $data));
    }
    flock($fp, LOCK_UN); // 释放锁
}
fclose($fp);

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

        # 放行证书和反代相关的 API 请求
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
            'ip_info' => '获取中...', // 【优化 2】配合前端异步请求 IP 归属地，后端直接返回默认值
            'token'   => $token,
            'status'  => $status,
            'ua'      => $ua
        ];

        // 【优化 3】已删掉原先的 if (count($result) >= 100) break; 限制，解除 100 条上限
    }
}

echo json_encode($result, JSON_UNESCAPED_UNICODE);
exit;
