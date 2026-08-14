<?php
require_once __DIR__ . '/auth.php';
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');

date_default_timezone_set('Asia/Shanghai');

$logFile = '/opt/SubMonitor/rules/access.log';

$emptyAnalytics = [
    'top_ips'    => [],
    'top_tokens' => [],
    'sus_tokens' => [],
    'sus_ips'    => []
];

if (!file_exists($logFile) || !($fp = fopen($logFile, 'r'))) {
    echo json_encode([
        'total'         => 0,
        'total_ips'     => 0,
        'total_success' => 0,
        'total_error'   => 0,
        'analytics'     => $emptyAnalytics,
        'page'          => 1,
        'limit'         => 50,
        'data'          => []
    ], JSON_UNESCAPED_UNICODE);
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

// 状态码与中文备注映射表
$remarkMap = [
    '200' => '拉取订阅',
    '400' => '伪造请求',
    '401' => '未授权请求',
    '403' => '异常用户',
    '404' => '路径错误',
    '429' => '请求过多',
    '500' => '服务异常',
    '502' => '服务异常',
    '503' => '服务异常'
];

/**
 * 仅从本地缓存中快速获取 IP 归属地，禁止进行同步 HTTP 外网请求
 */
function getIpInfoFromCache($ip, $ipCache) {
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        return '本地/局域网';
    }
    return $ipCache[$ip] ?? '';
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

        // 从本地缓存读取 IP 归属地
        $ipInfo = getIpInfoFromCache($ip, $ipCache);

        // 拼接中文备注（解决搜索“拉取订阅”等无结果的问题）
        $remarkText = $remarkMap[$status] ?? '';

        // 搜索词过滤（支持搜索 IP、归属地、Token、UA、状态码、中文备注）
        if ($search !== '') {
            $searchableText = mb_strtolower($ip . ' ' . $ipInfo . ' ' . $token . ' ' . $ua . ' ' . $status . ' ' . $remarkText . ' ' . $formattedTime . ' ' . $line);
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

// 3. 计算全局 Analytics 统计卡片数据
$todayStr = date('Y-m-d');

// TOP IP (仅统计今日)
$topIpStats = [];
// TOP TOKEN (仅统计今日)
$topTokenStats = [];
// 可疑 TOKEN (全局多 IP)
$tokenIpMap = [];
// 可疑 IP (全局多 TOKEN)
$ipTokenMap = [];

foreach ($parsedLines as $item) {
    $ip = $item['ip'];
    $token = $item['token'];
    $time = $item['time'];
    $info = $item['ip_info'];

    // 今日数据聚类
    if (strpos($time, $todayStr) === 0) {
        if ($ip && $ip !== '-') {
            if (!isset($topIpStats[$ip])) {
                $topIpStats[$ip] = ['ip' => $ip, 'count' => 0, 'info' => $info];
            }
            $topIpStats[$ip]['count']++;
        }

        if ($token && $token !== '-') {
            if (!isset($topTokenStats[$token])) {
                $topTokenStats[$token] = ['token' => $token, 'count' => 0, 'lastTime' => $time];
            }
            $topTokenStats[$token]['count']++;
            if ($time > $topTokenStats[$token]['lastTime']) {
                $topTokenStats[$token]['lastTime'] = $time;
            }
        }
    }

    // 可疑行为关联映射
    if ($token && $token !== '-' && $ip && $ip !== '-') {
        if (!isset($tokenIpMap[$token])) {
            $tokenIpMap[$token] = [];
        }
        $tokenIpMap[$token][$ip] = true;

        if (!isset($ipTokenMap[$ip])) {
            $ipTokenMap[$ip] = ['tokens' => [], 'info' => $info];
        }
        $ipTokenMap[$ip]['tokens'][$token] = true;
    }
}

// 排序并格式化 TOP IP
usort($topIpStats, function($a, $b) {
    return $b['count'] - $a['count'];
});
$topIpList = array_slice($topIpStats, 0, 10);

// 排序并格式化 TOP TOKEN
usort($topTokenStats, function($a, $b) {
    return $b['count'] - $a['count'];
});
$topTokenList = array_slice($topTokenStats, 0, 10);

// 提取可疑 Token (IP 数 > 1)
$susTokenStats = [];
foreach ($tokenIpMap as $t => $ips) {
    $ipCount = count($ips);
    if ($ipCount > 1) {
        $susTokenStats[] = ['token' => $t, 'ipCount' => $ipCount];
    }
}
usort($susTokenStats, function($a, $b) {
    return $b['ipCount'] - $a['ipCount'];
});
$susTokenList = array_slice($susTokenStats, 0, 10);

// 提取可疑 IP (Token 数 > 1)
$susIpStats = [];
foreach ($ipTokenMap as $ip => $data) {
    $tokenCount = count($data['tokens']);
    if ($tokenCount > 1) {
        $susIpStats[] = ['ip' => $ip, 'tokenCount' => $tokenCount, 'info' => $data['info']];
    }
}
usort($susIpStats, function($a, $b) {
    return $b['tokenCount'] - $a['tokenCount'];
});
$susIpList = array_slice($susIpStats, 0, 10);

$analytics = [
    'top_ips'    => $topIpList,
    'top_tokens' => $topTokenList,
    'sus_tokens' => $susTokenList,
    'sus_ips'    => $susIpList
];

// 4. 分页切片
$page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
$limit = isset($_GET['limit']) ? max(1, intval($_GET['limit'])) : 50;
$pagedData = array_slice($parsedLines, ($page - 1) * $limit, $limit);

// 5. 返回 JSON
echo json_encode([
    'total'         => $total,
    'total_ips'     => $totalIps,      // 全局独立 IP 数
    'total_success' => $totalSuccess,  // 全局成功数
    'total_error'   => $totalError,    // 全局异常拦截数
    'analytics'     => $analytics,     // 全局分析卡片数据
    'page'          => $page,
    'limit'         => $limit,
    'data'          => $pagedData
], JSON_UNESCAPED_UNICODE);
exit;
