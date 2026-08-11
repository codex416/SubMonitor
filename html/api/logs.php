<?php
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');

// 强制设置默认时区为 UTC+8
date_default_timezone_set('Asia/Shanghai');

$logFile = '/etc/nginx/rules/access.log';
$cacheFile = '/tmp/ip_cache.json'; // IP 归属地持久化磁盘缓存文件

if (!file_exists($logFile)) {
    echo json_encode([]);
    exit;
}

// 1. 读取本地磁盘持久化 IP 缓存
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
        'http' => [
            'timeout' => 1,
            'header'  => "User-Agent: Mozilla/5.0\r\n"
        ]
    ]);

    $res = @file_get_contents("http://ip-api.com/json/{$ip}?lang=zh-CN", false, $ctx);
    if ($res) {
        $data = json_decode($res, true);
        if ($data && isset($data['status']) && $data['status'] === 'success') {
            $info = sprintf("%s %s %s %s", 
                $data['country'] ?? '', 
                $data['regionName'] ?? '', 
                $data['city'] ?? '', 
                $data['isp'] ?? ''
            );
            $info = trim($info) ?: '公网 IP';
            $ipCache[$ip] = $info;
            $cacheUpdated = true;
            return $info;
        }
    }

    return "公网 IP";
}

// 2. 读取日志末尾 128KB
$fp = fopen($logFile, 'r');
if (!$fp) {
    echo json_encode([]);
    exit;
}
$size = filesize($logFile);
$readSize = min($size, 131072);
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
$lines = array_slice($lines, 0, 200);

$result = [];
$targetTimeZone = new DateTimeZone('Asia/Shanghai');

foreach ($lines as $line) {
    if (preg_match('/^(\S+) \S+ \S+ \[(.*?)\] "(?:GET|POST|HEAD) (\S+) HTTP\/[^"]+" (\d{3}) \d+ "([^"]*)" "([^"]*)"/', $line, $matches)) {
        $ip      = $matches[1];
        $timeRaw  = $matches[2];
        $url      = $matches[3];
        $status   = $matches[4];
        $referer  = $matches[5];
        $ua       = $matches[6];

        $token = '-';
        $queryString = parse_url($url, PHP_URL_QUERY);
        if ($queryString) {
            parse_str($queryString, $queryParams);
            if (!empty($queryParams['token'])) {
                $token = $queryParams['token'];
            }
        }

        // 解析日志原始时间，并显式转换为 UTC+8 格式
        $dt = DateTime::createFromFormat('d/M/Y:H:i:s O', $timeRaw);
        if ($dt) {
            $dt->setTimezone($targetTimeZone);
            $formattedTime = $dt->format('Y-m-d H:i:s');
        } else {
            $formattedTime = $timeRaw;
        }

        $result[] = [
            'time'    => $formattedTime,
            'ip'      => $ip,
            'ip_info' => getIpLocation($ip, $ipCache, $cacheUpdated),
            'token'   => $token,
            'status'  => $status,
            'ua'      => $ua
        ];
    }
}

// 4. 更新磁盘缓存
if ($cacheUpdated) {
    @file_put_contents($cacheFile, json_encode($ipCache, JSON_UNESCAPED_UNICODE));
}

// 直接输出纯数组供前端解析
echo json_encode($result, JSON_UNESCAPED_UNICODE);
