<?php
require_once __DIR__ . '/auth.php';
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');

date_default_timezone_set('Asia/Shanghai');

$logFile = '/opt/SubMonitor/rules/access.log';

if (!file_exists($logFile)) {
    echo json_encode(['total' => 0, 'page' => 1, 'limit' => 50, 'data' => []], JSON_UNESCAPED_UNICODE);
    exit;
}

$fp = fopen($logFile, 'r');
if (!$fp) { 
    echo json_encode(['total' => 0, 'page' => 1, 'limit' => 50, 'data' => []], JSON_UNESCAPED_UNICODE);
    exit;
}

$lines = [];
if (flock($fp, LOCK_SH)) {
    $size = filesize($logFile);
    $readSize = min($size, 262144);
    if ($readSize > 0) {
        fseek($fp, $size - $readSize);
        $data = fread($fp, $readSize);
        $lines = array_filter(explode("\n", $data));
    }
    flock($fp, LOCK_UN);
}
fclose($fp);

$lines = array_reverse($lines);
$targetTimeZone = new DateTimeZone('Asia/Shanghai');

// 加载本地 IP 缓存
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

// 1. 先对所有原始日志行进行正则筛选和过滤（确保 total 计算准确）
$validLines = [];
foreach ($lines as $line) {
    if (preg_match('/^(\S+) \S+ \S+ \[(.*?)\] "(?:GET|POST|HEAD) (\S+) HTTP\/[^"]+" (\d{3}) \d+ "([^"]*)" "([^"]*)"/', $line, $matches)) {
        $url = $matches[3];
        $parsedUrl = parse_url($url);
        $path = $parsedUrl['path'] ?? $url;

        # 放行证书和反代相关的 API 请求
        if ((strpos($url, '/api/') !== false && strpos($url, 'cert') === false && strpos($url, 'domain') === false) || $path === '/' || $path === '/index.html' || $path === '/login.html' || preg_match('/\.(js|css|ico|png|jpg|html|txt|woff)$/i', $path)) {
            continue;
        }
        $validLines[] = $line;
    }
}

$total = count($validLines);

// 2. 获取分页参数并对有效行进行切片（只取当前页需要的几十行）
$page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
$limit = isset($_GET['limit']) ? max(1, intval($_GET['limit'])) : 50;
$pagedLines = array_slice($validLines, ($page - 1) * $limit, $limit);

$result = [];

// 3. 只针对当前页的几十行进行解析和 IP 归属地查询，极大提升性能
foreach ($pagedLines as $line) {
    if (preg_match('/^(\S+) \S+ \S+ \[(.*?)\] "(?:GET|POST|HEAD) (\S+) HTTP\/[^"]+" (\d{3}) \d+ "([^"]*)" "([^"]*)"/', $line, $matches)) {
        $ip = $matches[1];
        $timeRaw = $matches[2];
        $url = $matches[3];
        $status = $matches[4];
        $ua = $matches[6];

        $parsedUrl = parse_url($url);
        $path = $parsedUrl['path'] ?? $url;

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

        // 仅对当前页的 IP 进行查询
        $ipInfo = getIpInfoFast($ip, $ipCache, $cacheChanged);

        $result[] = [
            'time'    => $formattedTime,
            'ip'      => $ip,
            'ip_info' => $ipInfo,
            'token'   => $token,
            'status'  => $status,
            'ua'      => $ua
        ];
    }
}

// 如果缓存有新增内容，统一保存到文件
if ($cacheChanged) {
    @file_put_contents($cacheFile, json_encode($ipCache, JSON_UNESCAPED_UNICODE));
}

// 4. 返回友好的对象结构
echo json_encode([
    'total' => $total,
    'page'  => $page,
    'limit' => $limit,
    'data'  => $result
], JSON_UNESCAPED_UNICODE);
exit;
