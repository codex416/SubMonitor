<?php
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');

$logFile = '/var/log/nginx/sub_access.log';

if (!file_exists($logFile)) {
    echo json_encode([]);
    exit;
}

function getIpLocation($ip) {
    if (!$ip || $ip === '-') return '未知';
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        return "局域网 IP";
    }

    static $cache = [];
    if (isset($cache[$ip])) return $cache[$ip];

    $ctx = stream_context_create(['http' => ['timeout' => 1]]);
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
            $cache[$ip] = trim($info);
            return $cache[$ip];
        }
    }
    return "公网 IP";
}

$lines = array_slice(file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES), -1000);
$result = [];

foreach (array_reverse($lines) as $line) {
    if (preg_match('/^(\S+) \S+ \S+ \[(.*?)\] "(?:GET|POST) (\S+) HTTP\/\d\.\d" (\d{3}) \d+ "([^"]+)"/', $line, $matches)) {
        $ip = $matches[1];
        $timeRaw = $matches[2];
        $url = $matches[3];
        $status = $matches[4];
        $ua = $matches[5];

        $token = '-';
        $queryString = parse_url($url, PHP_URL_QUERY);
        if ($queryString) {
            parse_str($queryString, $queryParams);
            if (!empty($queryParams['token'])) {
                $token = $queryParams['token'];
            }
        }

        $dt = DateTime::createFromFormat('d/M/Y:H:i:s O', $timeRaw);
        $formattedTime = $dt ? $dt->format('Y-m-d H:i:s') : $timeRaw;

        $result[] = [
            'time' => $formattedTime,
            'ip' => $ip,
            'ip_info' => getIpLocation($ip),
            'token' => $token,
            'status' => $status,
            'ua' => $ua
        ];
    }
}

echo json_encode($result);
