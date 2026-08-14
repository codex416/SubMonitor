<?php
require_once __DIR__ . '/auth.php';
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');

date_default_timezone_set('Asia/Shanghai');

$logFile = '/opt/SubMonitor/rules/access.log';

if (!file_exists($logFile)) {
    echo json_encode(['total' => 0, 'data' => []], JSON_UNESCAPED_UNICODE);
    exit;
}

// 【新增】接收前端传来的分页参数，默认第 1 页，每页 50 条
$page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
$limit = isset($_GET['limit']) ? max(1, intval($_GET['limit'])) : 50;
$offset = ($page - 1) * $limit;

$fp = fopen($logFile, 'r');
if (!$fp) { 
    echo json_encode(['total' => 0, 'data' => []], JSON_UNESCAPED_UNICODE); 
    exit; 
}

$lines = [];
// 加上文件共享锁，确保高并发写入时读取安全
if (flock($fp, LOCK_SH)) {
    $size = filesize($logFile);
    $readSize = min($size, 1048576); // 适当加大读取窗口（1MB），确保分页能获取更多历史数据
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

// 加载本地 IP 缓存，避免每次实时请求第三方 API 造成卡顿
$cacheFile = '/opt/SubMonitor/rules/ip_cache.json';
$ipCache = file_exists($cacheFile) ? json_decode(file_get_contents($cacheFile), true) : [];
$cacheChanged = false;

function getIpInfoFast($ip, &$ipCache, &$cacheChanged) {
    if ($ip === '127.0.0.1' || $ip === '::1' || strpos($ip, '192.168.') === 0 || strpos($ip, '10.') === 0 || strpos($ip, '172.') === 0) {
        return '本地/局域网';
    }
    if (isset($ipCache[$ip])) {
        return $ipCache[$ip];
    }
    
    $ctx = stream_context_create(['http' => ['timeout' => 0.8]]);
    $res = @file_get_contents("http://ip-api.com/json/{$ip}?lang=zh-CN", false, $ctx);
    
    $info = '未知归属地';
    if ($res) {
        $data = json_decode($res, true);
        if ($data && $data['status'] === 'success') {
            $info = trim(($data['country'] ?? '') . ' ' . ($data['regionName'] ?? '') . ' ' . ($data['city'] ?? ''));
        }
    }
    
    $ipCache[$ip] = $info;
    $cacheChanged = true;
    return $info;
}

$matchedLogs = [];

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

        // 暂存所有通过过滤的日志
        $matchedLogs[] = [
            'time'    => $formattedTime,
            'ip'      => $ip,
            'ip_info' => '', // 稍后只对当前页计算归属地，大幅提升性能！
            'token'   => $token,
            'status'  => $status,
            'ua'      => $ua,
            'raw_ip'  => $ip // 用于后续获取归属地
        ];
    }
}

// 获取符合条件的总条数
$total = count($matchedLogs);

// 【核心分页切片】只截取当前页需要的数据
$pageLogs = array_slice($matchedLogs, $offset, $limit);

// 循环当前页数据，查询 IP 归属地（大幅减少第三方 API 请求次数）
foreach ($pageLogs as $item) {
    $ipInfo = getIpInfoFast($item['raw_ip'], $ipCache, $cacheChanged);
    $result[] = [
        'time'    => $item['time'],
        'ip'      => $item['ip'],
        'ip_info' => $ipInfo,
        'token'   => $item['token'],
        'status'  => $item['status'],
        'ua'      => $item['ua']
    ];
}

// 如果缓存有新增内容，统一保存到文件
if ($cacheChanged) {
    @file_put_contents($cacheFile, json_encode($ipCache, JSON_UNESCAPED_UNICODE));
}

// 返回结构化分页数据
echo json_encode([
    'total' => $total,
    'page'  => $page,
    'limit' => $limit,
    'data'  => $result
], JSON_UNESCAPED_UNICODE);
exit;
