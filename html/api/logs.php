<?php
require_once __DIR__ . '/auth.php';
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');

date_default_timezone_set('Asia/Shanghai');

$logFile = '/opt/SubMonitor/rules/access.log';

if (!file_exists($logFile) || !($fp = fopen($logFile, 'r'))) {
    echo json_encode(['total' => 0, 'total_ips' => 0, 'total_success' => 0, 'total_error' => 0, 'page' => 1, 'limit' => 50, 'data' => []], JSON_UNESCAPED_UNICODE);
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

// 接收筛选参数
$search = isset($_GET['search']) ? mb_strtolower(trim($_GET['search'])) : '';
$startTime = isset($_GET['start_time']) ? trim($_GET['start_time']) : '';
$endTime = isset($_GET['end_time']) ? trim($_GET['end_time']) : '';

// 加载本地 IP 缓存
$cacheFile = '/opt/SubMonitor/rules/ip_cache.json';
$ipCache = file_exists($cacheFile) ? json_decode(file_get_contents($cacheFile), true) : [];
$cacheChanged = false;

/**
 * 快速获取 IP 归属地及运营商信息
 */
function getIpInfoFast($ip, &$ipCache, &$cacheChanged) {
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
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
        if ($data && isset($data['status']) && $data['status'] === 'success') {
            $location = trim(($data['country'] ?? '') . ' ' . ($data['regionName'] ?? '') . ' ' . ($data['city'] ?? ''));
            $isp = $data['isp'] ?? ($data['org'] ?? '');
            $info = $isp ? trim($location . ' (' . $isp . ')') : $location;
        }
    }
    
    $ipCache[$ip] = $info;
    $cacheChanged = true;
    return $info;
}

// 1. 全局解析与筛选
$parsedLines = [];
foreach ($lines as $line) {
    if (preg_match('/^(\S+) \S+ \S+ \[(.*?)\] "(?:GET|POST|HEAD) (\S+) HTTP\/[^"]+" (\d{3}) \d+ "([^"]*)" "([^"]*)"/', $line, $matches)) {
        $ip = $matches[1];
        $timeRaw = $matches[2];
        $url = $matches[3];
        $status = $matches[4];
        $ua = $matches[6];

        $parsedUrl = parse_url($url);
        $path = $parsedUrl['path'] ?? $url;

        // 放行证书和反代相关的 API 请求
        if ((strpos($url, '/api/') !== false && strpos($url, 'cert') === false && strpos($url, 'domain') === false) || $path === '/' || $path === '/index.html' || $path === '/login.html' || preg_match('/\.(js|css|ico|png|jpg|html|txt|woff)$/i', $path)) {
            continue;
        }

        // 解析 Token
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

        // 解析并转换格式化时间
        $dt = DateTime::createFromFormat('d/M/Y:H:i:s O', $timeRaw);
        $formattedTime = $dt ? $dt->setTimezone($targetTimeZone)->format('Y-m-d H:i:s') : $timeRaw;

        // 时间范围过滤
        if ($startTime !== '' || $endTime !== '') {
            if ($formattedTime) {
                if ($startTime !== '' && $formattedTime < $startTime) continue;
                if ($endTime !== '' && $formattedTime > $endTime) continue;
            }
        }

        // 预查或使用缓存中的 IP 归属地以支持地区搜索
        $ipInfo = getIpInfoFast($ip, $ipCache, $cacheChanged);

        // 搜索词过滤（支持搜索 IP、归属地、Token、UA、状态码）
        if ($search !== '') {
            $searchableText = mb_strtolower($ip . ' ' . $ipInfo . ' ' . $token . ' ' . $ua . ' ' . $status . ' ' . $formattedTime . ' ' . $line);
            if (strpos($searchableText, $search) === false) {
                continue;
            }
        }

        $parsedLines[] = [
            'time'    => $formattedTime,
            'ip'      => $ip,
            'ip_info' => $ipInfo,
            'token'   => $token,
            'status'  => $status,
            'ua'      => $ua
        ];
    }
}

// 2. 全局统计数据计算
$total = count($parsedLines);
$globalIps = [];
$totalSuccess = 0;
$totalError = 0;

foreach ($parsedLines as $item) {
    $globalIps[$item['ip']] = true;
    if ($item['status'] === '200') {
        $totalSuccess++;
    } else {
        $totalError++;
    }
}
$totalIps = count($globalIps);

// 3. 分页切片
$page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
$limit = isset($_GET['limit']) ? max(1, intval($_GET['limit'])) : 50;
$pagedData = array_slice($parsedLines, ($page - 1) * $limit, $limit);

if ($cacheChanged) {
    @file_put_contents($cacheFile, json_encode($ipCache, JSON_UNESCAPED_UNICODE));
}

// 4. 返回 JSON
echo json_encode([
    'total'         => $total,
    'total_ips'     => $totalIps,      // 全局独立 IP 数
    'total_success' => $totalSuccess,  // 全局成功数
    'total_error'   => $totalError,    // 全局异常拦截数
    'page'          => $page,
    'limit'         => $limit,
    'data'          => $pagedData
], JSON_UNESCAPED_UNICODE);
exit;
