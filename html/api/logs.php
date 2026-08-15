<?php
require_once __DIR__ . '/auth.php';
header('Content-Type: application/json; charset=utf-8');

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
    // 必须读取完整日志文件，才能保证“全部时间 / 今天 / 昨天 / 近3天 / 近7天 / 自定义时间”真正覆盖对应时间范围。
    // 原版本只读取最后 256KB，会导致较早日志、统计和时间筛选被静默截断。
    $data = stream_get_contents($fp);
    if ($data !== false && $data !== '') {
        $lines = array_values(array_filter(explode("\n", $data), static function ($line) {
            return trim($line) !== '';
        }));
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

// 加载本地 IP 缓存（修正2：安全校验 json_decode 结果）
$cacheFile = '/opt/SubMonitor/rules/ip_cache.json';
$ipCacheRaw = file_exists($cacheFile) ? json_decode(file_get_contents($cacheFile), true) : null;
$ipCache = is_array($ipCacheRaw) ? $ipCacheRaw : [];

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
 * IP 归属地：先读本地缓存；新 IP 没有缓存时由服务器查询并立即写入缓存。
 * 不把“未知地区”写入缓存，避免一次失败永久污染缓存。
 */
function getIpInfoFromCache($ip, &$ipCache) {
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        return '本地/局域网';
    }

    $cached = $ipCache[$ip] ?? '';
    if (is_array($cached)) {
        $cached = $cached['info'] ?? ($cached['location'] ?? '');
    }
    $cached = is_string($cached) ? trim($cached) : '';

    return ($cached !== '' && $cached !== '未知地区') ? $cached : '';
}

function queryIpGeo($ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        return '';
    }

    $urls = [
        'https://ipwho.is/' . rawurlencode($ip) . '?lang=zh-CN',
        'https://ipapi.co/' . rawurlencode($ip) . '/json/'
    ];

    foreach ($urls as $url) {
        $body = false;
        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_CONNECTTIMEOUT => 2,
                CURLOPT_TIMEOUT => 4,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_USERAGENT => 'SubMonitor/1.0',
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2
            ]);
            $body = curl_exec($ch);
            curl_close($ch);
        } else {
            $ctx = stream_context_create(['http' => ['timeout' => 4, 'ignore_errors' => true]]);
            $body = @file_get_contents($url, false, $ctx);
        }

        if (!is_string($body) || $body === '') continue;
        $data = json_decode($body, true);
        if (!is_array($data)) continue;

        $success = $data['success'] ?? true;
        if ($success === false || !empty($data['error'])) continue;

        $country = $data['country'] ?? ($data['country_name'] ?? '');
        $region  = $data['region'] ?? ($data['region_name'] ?? '');
        $city    = $data['city'] ?? '';
        $org     = '';
        if (isset($data['connection']) && is_array($data['connection'])) {
            $org = $data['connection']['org'] ?? ($data['connection']['isp'] ?? '');
        }
        if ($org === '') $org = $data['org'] ?? ($data['asn'] ?? '');

        $parts = array_filter([$country, $region, $city, $org !== '' ? '(' . $org . ')' : ''], static function ($v) {
            return trim((string)$v) !== '';
        });
        $info = trim(implode(' ', $parts));
        if ($info !== '') return $info;
    }

    return '';
}
// 1. 全局基础解析与提取
$allParsedLines = [];
foreach ($lines as $line) {
    if (preg_match('/^(\S+) \S+ \S+ \[(.*?)\] "(?:GET|POST|HEAD) (\S+) HTTP\/[^"]+" (\d{3}) \d+ "([^"]*)" "([^"]*)"/', $line, $matches)) {
        $ip = $matches[1];
        $timeRaw = $matches[2];
        $url = $matches[3];
        $status = $matches[4];
        $ua = $matches[6];

        $parsedUrl = parse_url($url);
        $path = $parsedUrl['path'] ?? $url;

        // 修正3：将放行校验仅针对 $path 进行匹配，防止 Query 参数（如 ?ref=domain）引发误判
        if ((strpos($path, '/api/') !== false && strpos($path, 'cert') === false && strpos($path, 'domain') === false) || $path === '/' || $path === '/index.html' || $path === '/login.html' || preg_match('/\.(js|css|ico|png|jpg|html|txt|woff)$/i', $path)) {
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
        $formattedTime = $dt ? $dt->setTimezone($targetTimeZone)->format('Y-m-d H:i:s') : '';

        // 从本地缓存读取；新 IP 无缓存时由服务器查询。
        $ipInfo = getIpInfoFromCache($ip, $ipCache);
        if ($ipInfo === '') {
            $geo = queryIpGeo($ip);
            if ($geo !== '') {
                $ipInfo = $geo;
                $ipCache[$ip] = $geo;
            } else {
                $ipInfo = '未知地区';
            }
        }

        // 拼接中文备注
        $remarkText = $remarkMap[$status] ?? '';

        $allParsedLines[] = [
            'time'        => $formattedTime,
            'time_raw'    => $timeRaw,
            'ip'          => $ip,
            'ip_info'     => $ipInfo,
            'token'       => $token,
            'status'      => $status,
            'ua'          => $ua,
            'remark_text' => $remarkText,
            'raw_line'    => $line
        ];
    }
}

// 持久化本次补充的 IP 归属地缓存。
if (!empty($ipCache)) {
    $cacheDir = dirname($cacheFile);
    if (is_dir($cacheDir) && is_writable($cacheDir)) {
        @file_put_contents($cacheFile, json_encode($ipCache, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), LOCK_EX);
    }
}

// 2. 修正4：全局 Analytics 统计卡片（基于读取到的所有符合条件的原始日志进行统计，不受搜索/时间过滤干扰）
$todayStr = date('Y-m-d');
$topIpStats = [];
$topTokenStats = [];
$tokenIpMap = [];
$ipTokenMap = [];

foreach ($allParsedLines as $item) {
    $ip = $item['ip'];
    $token = $item['token'];
    $time = $item['time'];
    $info = $item['ip_info'];

    // 今日数据聚类
    if ($time !== '' && strpos($time, $todayStr) === 0) {
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
$topIpList = array_values($topIpStats);

// 排序并格式化 TOP TOKEN
usort($topTokenStats, function($a, $b) {
    return $b['count'] - $a['count'];
});
$topTokenList = array_values($topTokenStats);

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
$susTokenList = array_values($susTokenStats);

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
$susIpList = array_values($susIpStats);

$analytics = [
    'top_ips'    => $topIpList,
    'top_tokens' => $topTokenList,
    'sus_tokens' => $susTokenList,
    'sus_ips'    => $susIpList
];

// 3. 搜索与时间条件筛选（针对列表展示）
$filteredLines = [];
$globalIps = [];
$totalSuccess = 0;
$totalError = 0;

foreach ($allParsedLines as $item) {
    $formattedTime = $item['time'];

    // 时间范围过滤（修正5：增强时间解析失败时的安全性）
    if ($startTime !== '' || $endTime !== '') {
        if ($formattedTime === '') {
            continue; 
        }
        if ($startTime !== '' && $formattedTime < $startTime) continue;
        if ($endTime !== '' && $formattedTime > $endTime) continue;
    }

    // 搜索词过滤
    if ($search !== '') {
        $searchableText = mb_strtolower(
            $item['ip'] . ' ' . 
            $item['ip_info'] . ' ' . 
            $item['token'] . ' ' . 
            $item['ua'] . ' ' . 
            $item['status'] . ' ' . 
            $item['remark_text'] . ' ' . 
            $formattedTime . ' ' . 
            $item['raw_line']
        );
        if (strpos($searchableText, $search) === false) {
            continue;
        }
    }

    // 汇总当前筛选列表对应的统计指标
    $globalIps[$item['ip']] = true;
    if ($item['status'] === '200') {
        $totalSuccess++;
    } else {
        $totalError++;
    }

    $filteredLines[] = [
        'time'    => $formattedTime ?: $item['time_raw'],
        'ip'      => $item['ip'],
        'ip_info' => $item['ip_info'],
        'token'   => $item['token'],
        'status'  => $item['status'],
        'ua'      => $item['ua']
    ];
}

$total = count($filteredLines);
$totalIps = count($globalIps);

// 4. 分页切片
$page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
$limit = isset($_GET['limit']) ? max(1, intval($_GET['limit'])) : 50;
$pagedData = array_slice($filteredLines, ($page - 1) * $limit, $limit);

// 5. 返回 JSON
echo json_encode([
    'total'         => $total,
    'total_ips'     => $totalIps,      // 当前条件下的独立 IP 数
    'total_success' => $totalSuccess,  // 当前条件下的成功数
    'total_error'   => $totalError,    // 当前条件下的异常拦截数
    'analytics'     => $analytics,     // 全局分析卡片数据
    'page'          => $page,
    'limit'         => $limit,
    'data'          => $pagedData
], JSON_UNESCAPED_UNICODE);
exit;
