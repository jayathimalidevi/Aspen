<?php
// Local PHP built-in server: serve real files (style.css, etc.)
if (PHP_SAPI === 'cli-server') {
    $reqPath = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
    if ($reqPath !== '/' && is_file(__DIR__ . $reqPath)) return false;
}

// Railway healthcheck — must never be blocked or throttled
$__earlyPath = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if ($__earlyPath === '/health') {
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store');
    echo 'OK';
    exit;
}

$__skipBotGate = $__earlyPath === '/robots.txt'
    || preg_match('#^/sitemap(?:-jobs\d+)?\.xml$#', $__earlyPath)
    || preg_match('#^/google[a-z0-9]+\.html$#', $__earlyPath)
    || strpos($__earlyPath, '/.well-known/acme-challenge/') === 0;

define('CACHE_DIR', sys_get_temp_dir() . '/aspen-cache');

// ─── Production Error Handling ───────────────────────────────────────────────
ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);
register_shutdown_function(function () {
    $err = error_get_last();
    if ($err && in_array($err['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
        if (!headers_sent()) {
            http_response_code(500);
            header('Content-Type: text/plain; charset=utf-8');
            header('Cache-Control: no-store');
        }
        echo 'Something went wrong. Please try again shortly.';
    }
});

// ─── Security Headers ────────────────────────────────────────────────────────
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: https:; frame-ancestors 'none'; base-uri 'self'");
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: geolocation=(), camera=(), microphone=(), interest-cohort=()');
if (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https') {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}

$GOOGLE_BOTS = [
    'Googlebot', 'Googlebot-Image', 'Googlebot-News', 'Googlebot-Video',
    'Googlebot-Mobile', 'Storebot-Google', 'Google-InspectionTool',
    'AdsBot-Google', 'AdsBot-Google-Mobile', 'Mediapartners-Google',
];

// ─── Bot Gatekeeper ──────────────────────────────────────────────────────────
(function () use ($GOOGLE_BOTS, $__skipBotGate) {
    if ($__skipBotGate) return;
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
    if ($ua === '') return;

    static $allowPattern = null;
    if ($allowPattern === null) {
        $escaped = array_map(function ($b) { return preg_quote($b, '~'); }, $GOOGLE_BOTS);
        $allowPattern = '~\b(?:' . implode('|', $escaped) . ')\b~i';
    }
    if (preg_match($allowPattern, $ua)) return;

    static $BAD_BOTS = [
        'acunetix', 'addsearchbot', 'agenttimes', 'ahrefsbot', 'ai2bot',
        'ai2bot-deepresearcheval', 'ai2bot-dolma', 'aihitbot', 'aiwebindex',
        'amazon-kendra', 'amazon-qbusiness', 'amazonbot', 'amazonbuyforme',
        'amzn-searchbot', 'amzn-user', 'andibot', 'anomura', 'anthropic-ai',
        'apify', 'apifybot', 'apifywebsitecontentcrawler', 'applebot',
        'applebot-extended', 'aranet-searchbot', 'atlassian-bot', 'awario',
        'azureai', 'azureai-searchbot', 'backdoorbot', 'bedrockbot', 'bigsur.ai',
        'black hole', 'blexbot', 'bravebot', 'brightbot', 'brightbot 1.0',
        'buddybot', 'builtbottough', 'bytespider', 'ccbot', 'channel3bot',
        'chatglm', 'chatglm-spider', 'chatgpt', 'chatgpt agent', 'chatgpt-user',
        'claude', 'claude-code', 'claude-searchbot', 'claude-user', 'claude-web',
        'claudebot', 'cloudflare-autorag', 'cloudvertexbot', 'code', 'cohere',
        'cohere-ai', 'cohere-training-data-crawler', 'cotoyogi', 'cragcrawler',
        'crawl4ai', 'crawlspace', 'curl', 'cursor', 'dataforseo.com',
        'dataforseobot', 'datenbank', 'datenbank crawler', 'deepseek',
        'deepseekbot', 'devin', 'diffbot', 'diffbot-user', 'dotbot', 'doubaobot',
        'duckassistbot', 'easydl', 'echobot', 'echobot bot', 'echoboxbot',
        'erniebot', 'exabot', 'exasearchbot', 'facebookbot', 'facebookexternalhit',
        'factset', 'factset_spyderbot', 'firecrawl', 'firecrawlagent', 'flashget',
        'friendlycrawler', 'geisthaus', 'geisthaus-pagefetcher',
        'gemini-deep-research', 'getright', 'go-http-client', 'google-agent',
        'google-cloudvertexbot', 'google-extended', 'google-firebase',
        'google-gemini-cli', 'google-notebooklm', 'googleagent-mariner',
        'googleagent-urlcontext', 'googleother', 'googleother-image',
        'googleother-video', 'gptbot', 'havij', 'henkbot', 'httrack', 'iask',
        'iaskbot', 'iaskspider', 'iboubot', 'icc-crawler', 'imagesiftbot',
        'imagespider', 'img2dataset', 'isscyber', 'isscyberriskcrawler', 'kagi',
        'kagi-fetcher', 'kangaroo bot', 'kimi-searchbot', 'kimi-user', 'kimibot',
        'klaviyo', 'klaviyoaibot', 'kunato', 'kunatocrawler', 'laion',
        'laion-huggingface-processor', 'laiondownloader', 'larbin', 'lcc',
        'libwww-perl', 'lightpanda', 'linerbot', 'linguee', 'linguee bot',
        'linkup', 'linkupbot', 'manus-user', 'masscan', 'meta-external',
        'meta-externalagent', 'meta-externalfetcher', 'meta-webindexer',
        'mistralai', 'mistralai-index', 'mistralai-training', 'mistralai-user',
        'mj12bot', 'mozilla-tabstack', 'mycentralai', 'mycentralaiscraperbot',
        'nagetbot', 'netants', 'netestate', 'netestate imprint crawler', 'newsai',
        'nikto', 'nmap', 'notebooklm', 'novaact', 'nuclei', 'oai-adsbot',
        'oai-searchbot', 'offline explorer', 'omgili', 'omgilibot', 'openai',
        'opencode', 'operator', 'pangu', 'pangubot', 'panscient', 'panscient.com',
        'perplexity', 'perplexity-user', 'perplexitybot', 'petalbot', 'phind',
        'phindbot', 'poggio', 'poggio-citations', 'poseidon research',
        'poseidon research crawler', 'python-requests', 'qualifiedbot', 'querit',
        'querit-searchbot', 'queritbot', 'quillbot', 'quillbot.com', 'qwenbot',
        'reflectionbot', 'sbintuitions', 'sbintuitionsbot', 'scrapy', 'semrushbot',
        'semrushbot-ocob', 'semrushbot-swa', 'serpstatbot', 'shap-user', 'shapbot',
        'sidetrade', 'sidetrade indexer bot', 'sitesnagger', 'sitesucker',
        'spider', 'spyfu', 'sqlmap', 'stripper', 'sucker', 'tavily', 'tavilybot',
        'teleport', 'teleportpro', 'terra cotta', 'terracotta', 'thinkbot',
        'tiktokspider', 'timpibot', 'tongyibot', 'trae', 'twinagent', 'useai',
        'velen', 'velenpublicwebcrawler', 'wardbot', 'webcopier', 'webenhancer',
        'webreaper', 'webstripper', 'websucker', 'webzio', 'webzio-extended',
        'webzip', 'wget', 'widow', 'wpbot', 'wpscan', 'wrtn', 'wrtnbot',
        'xaldon_webspider', 'xenu', 'yak', 'yandexadditional',
        'yandexadditionalbot', 'yiyanbot', 'youbot', 'zanista', 'zanistabot',
        'zeus', 'zgrab', 'zmeu',
    ];

    static $blockPattern = null;
    if ($blockPattern === null) {
        $escaped = array_map(function ($b) { return preg_quote($b, '~'); }, $BAD_BOTS);
        $blockPattern = '~\b(?:' . implode('|', $escaped) . ')~i';
    }

    if (preg_match($blockPattern, $ua)) {
        http_response_code(403);
        header('Content-Type: text/plain; charset=utf-8');
        header('X-Robots-Tag: noindex, nofollow');
        echo "403 Forbidden";
        exit;
    }
})();

// ─── Per-IP Rate Limit ───────────────────────────────────────────────────────
(function () use ($GOOGLE_BOTS, $__skipBotGate) {
    if ($__skipBotGate) return;
    $RATE_LIMIT  = 120;
    $RATE_WINDOW = 3600;

    $ip = '';
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = trim(explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0]);
    } elseif (!empty($_SERVER['HTTP_X_REAL_IP'])) {
        $ip = trim($_SERVER['HTTP_X_REAL_IP']);
    } elseif (!empty($_SERVER['REMOTE_ADDR'])) {
        $ip = $_SERVER['REMOTE_ADDR'];
    }
    if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) return;

    $rlUa = $_SERVER['HTTP_USER_AGENT'] ?? '';
    static $rlAllowPattern = null;
    if ($rlAllowPattern === null) {
        $escaped = array_map(function ($b) { return preg_quote($b, '~'); }, $GOOGLE_BOTS);
        $rlAllowPattern = '~\b(?:' . implode('|', $escaped) . ')\b~i';
    }
    if (strpos($ip, '66.249.') === 0 || preg_match($rlAllowPattern, $rlUa)) return;

    $dir = CACHE_DIR;
    if (!is_dir($dir)) @mkdir($dir, 0755, true);

    if (mt_rand(1, 200) === 1) {
        foreach (glob($dir . '/rl_*.json') ?: [] as $f) {
            if (@filemtime($f) < time() - 2 * $RATE_WINDOW) @unlink($f);
        }
    }

    $file = $dir . '/rl_' . md5($ip) . '.json';
    $now  = time();
    $data = ['start' => $now, 'count' => 0];

    $fp = @fopen($file, 'c+');
    if ($fp === false) return;
    if (flock($fp, LOCK_EX)) {
        $raw   = stream_get_contents($fp);
        $saved = $raw ? json_decode($raw, true) : null;
        if (is_array($saved) && isset($saved['start'], $saved['count'])
            && ($now - $saved['start']) < $RATE_WINDOW) {
            $data = $saved;
        }
        $data['count']++;
        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, json_encode($data));
        fflush($fp);
        flock($fp, LOCK_UN);
    }
    fclose($fp);

    if ($data['count'] > $RATE_LIMIT) {
        $retry = max(1, $RATE_WINDOW - ($now - $data['start']));
        http_response_code(429);
        header('Content-Type: text/plain; charset=utf-8');
        header('Retry-After: ' . $retry);
        header('X-Robots-Tag: noindex, nofollow');
        echo "429 Too Many Requests";
        exit;
    }
})();

// ─── Constants ──────────────────────────────────────────────────────────────
define('JOBS_PER_PAGE', 21);
define('URLS_PER_SITEMAP', 12500);
define('PAGE_CACHE_DIR', CACHE_DIR . '/pages');
define('PAGE_CACHE_TTL', 3600);
define('PAGE_CACHE_MAX_FILES', 3000);

$_apiUrl = getenv('API_URL') ?: 'http://170.205.37.229:5097';
$_apiKey = getenv('API_TOKEN') ?: getenv('API_SECRET') ?: getenv('API_KEY') ?: '69704e100b850cb2404b9cee8f38f32721e933c4f767e2a3c5cf31420e4c3cda';
define('API_BASE', rtrim($_apiUrl, '/'));
define('API_KEY', $_apiKey);
define('API_TIMEOUT', 10);
define('API_TTL_LIST', 1800);
define('API_TTL_JOB', 21600);
define('API_TTL_INFO', 3600);

define('APPLY_DOMAIN', 'https://ihire.allboardsolutions.in');
function applyUrl($permalink) {
    $path = preg_replace('~^https?://[^/]+~', '', $permalink ?? '');
    return $path !== '' ? APPLY_DOMAIN . $path : APPLY_DOMAIN;
}

$CSS_VER = @filemtime(__DIR__ . '/style.css') ?: '1';

function inlineCSS() {
    static $cached = null;
    if ($cached !== null) return $cached;
    $css = @file_get_contents(__DIR__ . '/style.css');
    if ($css === false || $css === '') {
        global $CSS_VER;
        return $cached = '<link rel="stylesheet" href="/style.css?v=' . $CSS_VER . '">';
    }
    return $cached = '<style>' . $css . '</style>';
}

// ─── Site Config ────────────────────────────────────────────────────────────
$cfgRaw = @file_get_contents(__DIR__ . '/site-config.json');
if (!$cfgRaw) { http_response_code(500); die('Error: site-config.json not found.'); }
$cfg = json_decode($cfgRaw, true);
if (!$cfg) { http_response_code(500); die('Error: site-config.json is invalid JSON.'); }

$siteName    = getenv('SITE_NAME')   ?: ($cfg['siteName']   ?? 'Aspen');
$companyName = getenv('SITE_NAME')   ?: ($cfg['companyName'] ?? $siteName);
$siteDomain  = getenv('SITE_DOMAIN') ?: ($cfg['domain'] ?? '');
$baseUrl     = $siteDomain !== '' ? rtrim('https://' . $siteDomain, '/') : rtrim($cfg['baseUrl'] ?? '', '/');
if ($baseUrl === '') {
    $proto   = (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https' || ($_SERVER['HTTPS'] ?? '') === 'on') ? 'https' : 'http';
    $baseUrl = $proto . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost');
}
$tagline     = $cfg['tagline']       ?? '';
$heroTitle   = $cfg['heroTitle']     ?? "Remote Careers<br><em>Built For You</em>";
$metaDesc    = $cfg['metaDescription'] ?? '';
$metaKeywords= $cfg['metaKeywords']  ?? '';
$metaAuthor  = $cfg['metaAuthor']    ?? '';
$ogTitle     = $cfg['ogTitle']       ?? '';
$ogDesc      = $cfg['ogDescription'] ?? '';
$year        = date('Y');

$logoLetter     = $cfg['logoLetter']  ?? strtoupper(substr($companyName, 0, 1));
$faviconBg      = $cfg['faviconBg']  ?? '#15803D';
$faviconFg      = $cfg['faviconFg']  ?? '#FBBF24';
$faviconSvg = 'data:image/svg+xml,' . rawurlencode(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
    . '<rect width="32" height="32" rx="7" fill="' . $faviconBg . '"/>'
    . '<text x="16" y="22" font-family="Inter,Arial,sans-serif" font-size="14" font-weight="900" fill="' . $faviconFg . '" text-anchor="middle">' . $logoLetter . '</text>'
    . '</svg>'
);

$sidebarStat1Num = $cfg['sidebarStat1Num'] ?? '$72K+';
$sidebarStat1Lbl = $cfg['sidebarStat1Lbl'] ?? 'Median Salary';
$sidebarStat2Num = $cfg['sidebarStat2Num'] ?? 'Daily';
$sidebarStat2Lbl = $cfg['sidebarStat2Lbl'] ?? 'New Listings';

// ─── Job Categories with Emoji Icons ────────────────────────────────────────
$JOB_CATEGORIES = [
    ['keyword' => 'customer service',     'emoji' => '🎧'],
    ['keyword' => 'data entry',           'emoji' => '📋'],
    ['keyword' => 'virtual assistant',    'emoji' => '🤝'],
    ['keyword' => 'software development', 'emoji' => '💻'],
    ['keyword' => 'web developer',        'emoji' => '🌐'],
    ['keyword' => 'content writing',      'emoji' => '✍️'],
    ['keyword' => 'digital marketing',    'emoji' => '📣'],
    ['keyword' => 'graphic design',       'emoji' => '🎨'],
    ['keyword' => 'project management',   'emoji' => '📊'],
    ['keyword' => 'sales',                'emoji' => '💼'],
    ['keyword' => 'chat support',         'emoji' => '💬'],
    ['keyword' => 'call center',          'emoji' => '📞'],
    ['keyword' => 'technical support',    'emoji' => '🔧'],
    ['keyword' => 'bookkeeping',          'emoji' => '📒'],
    ['keyword' => 'healthcare',           'emoji' => '🏥'],
    ['keyword' => 'insurance',            'emoji' => '🛡️'],
    ['keyword' => 'recruiter',            'emoji' => '🔍'],
    ['keyword' => 'translation',          'emoji' => '🌍'],
    ['keyword' => 'transcription',        'emoji' => '🎙️'],
    ['keyword' => 'social media',         'emoji' => '📱'],
    ['keyword' => 'video editing',        'emoji' => '🎬'],
    ['keyword' => 'data analyst',         'emoji' => '📈'],
    ['keyword' => 'business analyst',     'emoji' => '🏢'],
    ['keyword' => 'finance',              'emoji' => '💰'],
    ['keyword' => 'marketing',            'emoji' => '🚀'],
    ['keyword' => 'design',               'emoji' => '🖌️'],
    ['keyword' => 'writing',              'emoji' => '📝'],
    ['keyword' => 'engineer',             'emoji' => '⚙️'],
];

$JOB_COUNTRIES = [
    ['name'=>'United States','iso'=>'US'],['name'=>'Japan','iso'=>'JP'],
    ['name'=>'India','iso'=>'IN'],['name'=>'United Kingdom','iso'=>'GB'],
    ['name'=>'Brazil','iso'=>'BR'],['name'=>'Australia','iso'=>'AU'],
    ['name'=>'Indonesia','iso'=>'ID'],['name'=>'Germany','iso'=>'DE'],
    ['name'=>'Netherlands','iso'=>'NL'],['name'=>'Sweden','iso'=>'SE'],
    ['name'=>'Canada','iso'=>'CA'],['name'=>'Mexico','iso'=>'MX'],
    ['name'=>'France','iso'=>'FR'],['name'=>'Spain','iso'=>'ES'],
    ['name'=>'South Korea','iso'=>'KR'],['name'=>'South Africa','iso'=>'ZA'],
    ['name'=>'Nigeria','iso'=>'NG'],
];

$JOB_IMAGES = [
    'beginner-remote-virtual-assistant-jobs-no-experience','bilingual-remote-call-center-jobs-spanish-english',
    'bilingual-remote-customer-service-jobs-spanish','contract-remote-jobs','customer-service-remote-positions',
    'entry-level-remote-data-entry-clerk-jobs','entry-level-remote-positions','entry-level-remote-virtual-assistant-positions',
    'entry-level-work-from-home-customer-service','evening-remote-chat-support-agent-jobs','evening-remote-work',
    'evening-work-from-home-data-entry-positions','evening-work-from-home-virtual-assistant-jobs',
    'flexible-remote-customer-service','flexible-remote-jobs','freelance-virtual-assistant-work-from-home-opportunities',
    'freelance-work-from-home-data-entry-opportunities','full-time-remote-customer-service-positions',
    'full-time-work-from-home','legitimate-work-from-home-data-entry-jobs','online-customer-service-representative',
    'online-customer-support-jobs','overnight-remote-call-center-agent-positions','overnight-remote-chat-support-representative',
    'overnight-remote-customer-service-jobs','overnight-remote-positions','part-time-remote-chat-support-no-experience',
    'part-time-remote-customer-support-jobs','part-time-remote-data-entry-no-experience','part-time-remote-jobs',
    'remote-customer-service-jobs','remote-data-entry-jobs','work-from-home-jobs-image',
];

// ─── Helpers ────────────────────────────────────────────────────────────────
function catKeyword($cat)  { return is_array($cat) ? $cat['keyword'] : $cat; }
function catLabel($cat)    { return 'Remote ' . ucwords(catKeyword($cat)) . ' Jobs'; }
function catUrl($cat)      { return categoryUrl(catKeyword($cat)); }
function catEmoji($cat)    { return is_array($cat) ? ($cat['emoji'] ?? '💼') : '💼'; }

function sanitizePostName($name) {
    if (!$name) return 'job';
    $s = strtolower($name);
    $s = preg_replace('/[^\w\s-]/', '', $s);
    $s = preg_replace('/\s+/', '-', $s);
    $s = preg_replace('/-+/', '-', $s);
    $s = trim($s);
    if (strlen($s) > 100) $s = rtrim(substr($s, 0, 100), '-');
    return $s ?: 'job';
}

function e($str) { return htmlspecialchars($str ?? '', ENT_QUOTES | ENT_HTML5, 'UTF-8'); }
function ej($str) {
    if (!$str) return '';
    return str_replace(["\n", "\r", "\t", '"', '\\'], ['\\n', '\\r', '\\t', '\\"', '\\\\'], $str);
}

function safeSubstr($str, $len) {
    return function_exists('mb_substr') ? mb_substr($str, 0, $len) : substr((string)$str, 0, $len);
}

function getJobDate($jobId) {
    $daysAgo = abs(crc32((string)$jobId)) % 3;
    return date('Y-m-d', strtotime("-{$daysAgo} days"));
}

function getJobDateLabel($jobId) {
    $daysAgo = abs(crc32((string)$jobId)) % 3;
    if ($daysAgo === 0) return 'Today';
    if ($daysAgo === 1) return 'Yesterday';
    return date('M j', strtotime("-{$daysAgo} days"));
}

function getJobImage($title, $postName) {
    global $JOB_IMAGES;
    $id = $postName ?: $title ?: 'default';
    $hash = crc32($id);
    return $JOB_IMAGES[abs($hash) % count($JOB_IMAGES)] . '.webp';
}

function jobCountry($jobId) {
    global $JOB_COUNTRIES;
    return $JOB_COUNTRIES[($jobId ?: 0) % count($JOB_COUNTRIES)];
}

function repairMojibake($s) {
    if (!$s || !function_exists('mb_convert_encoding')) return $s;
    if (!preg_match('/\xc3[\x82\xa2\xb0]\xc2[\x80-\xbf]/', $s)) return $s;
    $repaired = @mb_convert_encoding($s, 'ISO-8859-1', 'UTF-8');
    if ($repaired !== false && $repaired !== '' && mb_check_encoding($repaired, 'UTF-8')) return $repaired;
    return $s;
}

function brandReplace($text) {
    if (!is_string($text) || $text === '') return $text;
    global $companyName;
    static $pattern = null;
    if ($pattern === null) {
        $brands = ['Amazon', 'Aetna', 'Delta', 'CVS'];
        $pattern = '~\b(?:' . implode('|', array_map(function ($b) { return preg_quote($b, '~'); }, $brands)) . ')\b~i';
    }
    return preg_replace($pattern, $companyName, $text);
}

function sanitizeJobTitles($jobs) {
    if (!is_array($jobs)) return $jobs;
    foreach ($jobs as &$j) {
        if (is_array($j) && isset($j['post_title'])) $j['post_title'] = brandReplace($j['post_title']);
    }
    unset($j);
    return $jobs;
}

function formatJobContent($content) {
    if (!$content) return '';
    $content = repairMojibake($content);
    $content = preg_replace('/rjs\.victorytuitions\.in/i', '', $content);
    $content = preg_replace('/remotejobs\.trendingnews(?:go)?\.com/i', '', $content);
    $content = preg_replace('/\[\/?[a-z0-9_\-]+(?:[^\]]*)?\]/i', '', $content);
    $content = preg_replace('/<a\b[^>]*>(.*?)<\/a>/si', '$1', $content);
    $content = preg_replace('/\bapply to this job\b/i', '', $content);
    $allowed = '<p><br><strong><b><em><i><u><ul><ol><li><h1><h2><h3><h4><h5><h6><hr><blockquote><span><div>';
    $content = strip_tags($content, $allowed);
    $content = preg_replace('/\s*on[a-z]+\s*=\s*("[^"]*"|\'[^\']*\')/i', '', $content);
    $content = preg_replace('/\s*style\s*=\s*("[^"]*"|\'[^\']*\')/i', '', $content);
    $content = preg_replace('/(\r\n|\r)/', "\n", $content);
    $content = preg_replace("/\n{3,}/", "\n\n", $content);
    $content = trim($content);
    $content = preg_replace('/<\/?p\b[^>]*>/i', "\n\n", $content);
    $content = preg_replace("/\n{3,}/", "\n\n", trim($content));
    $blocks = preg_split('/\n\s*\n/', $content);
    $structured = [];
    foreach ($blocks as $b) {
        $b = trim($b);
        if ($b === '' || strlen($b) <= 800 || preg_match('/<(p|br|div|h[1-6]|ul|ol|li)\b/i', $b)) { $structured[] = $b; continue; }
        $headingPat = '/(?<=[.?!])\s+(Key (?:Details|Requirements|Responsibilities|Benefits|Skills|Qualifications)|Job Summary|Requirements|Responsibilities|Qualifications|Benefits|About (?:Us|the Role|the Company))(?=\s+[A-Z?])/u';
        $b = preg_replace($headingPat, "\n\n\$1\n\n", $b);
        $subBlocks = preg_split('/\n\s*\n/', $b);
        $rebuilt = [];
        foreach ($subBlocks as $sb) {
            $sb = trim($sb);
            if ($sb === '' || strlen($sb) <= 500) { $rebuilt[] = $sb; continue; }
            $sentences = preg_split('/(?<=[.!?])\s+(?=[A-Z])/', $sb);
            if (count($sentences) <= 3) { $rebuilt[] = $sb; continue; }
            for ($i = 0; $i < count($sentences); $i += 3) $rebuilt[] = trim(implode(' ', array_slice($sentences, $i, 3)));
        }
        $structured[] = implode("\n\n", $rebuilt);
    }
    $blocks = preg_split('/\n\s*\n/', implode("\n\n", $structured));
    $headingExact = '/^(Key (?:Details|Requirements|Responsibilities|Benefits|Skills|Qualifications)|Job Summary|Requirements|Responsibilities|Qualifications|Benefits|About (?:Us|the Role|the Company))[\s:]*$/u';
    $out = [];
    foreach ($blocks as $b) {
        $b = trim($b);
        if ($b === '') continue;
        if (trim(preg_replace('/<br\s*\/?>|&nbsp;|\s+/i', '', strip_tags($b))) === '') continue;
        if (preg_match('/^\s*<(div|h[1-6]|ul|ol|blockquote|hr|table)\b/i', $b)) { $out[] = $b; }
        elseif (preg_match($headingExact, $b)) { $out[] = '<h3>' . e($b) . '</h3>'; }
        else { $out[] = '<p>' . nl2br($b, false) . '</p>'; }
    }
    return implode("\n", $out);
}

// ─── API Client ─────────────────────────────────────────────────────────────
function apiGet($path, $ttl) {
    if (!is_dir(CACHE_DIR)) @mkdir(CACHE_DIR, 0755, true);
    $cachePath = CACHE_DIR . '/api_' . md5($path) . '.json';

    if (is_file($cachePath) && (time() - filemtime($cachePath)) < $ttl) {
        $cached = @file_get_contents($cachePath);
        if ($cached !== false) { $decoded = json_decode($cached, true); if ($decoded !== null) return $decoded; }
    }

    $url = API_BASE . $path;
    $body = false;
    $headers = ['Accept: application/json'];
    if (API_KEY !== '') $headers[] = 'X-Api-Key: ' . API_KEY;

    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => API_TIMEOUT, CURLOPT_CONNECTTIMEOUT => 5, CURLOPT_FOLLOWLOCATION => true, CURLOPT_HTTPHEADER => $headers]);
        $body = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($code !== 200) $body = false;
    } else {
        $ctx = stream_context_create(['http' => ['method' => 'GET', 'header' => implode("\r\n", $headers) . "\r\n", 'timeout' => API_TIMEOUT, 'ignore_errors' => true]]);
        $body = @file_get_contents($url, false, $ctx);
    }

    if ($body === false || $body === '') {
        if (is_file($cachePath)) { $stale = @file_get_contents($cachePath); return $stale !== false ? json_decode($stale, true) : null; }
        return null;
    }

    $data = json_decode($body, true);
    if ($data === null) return null;
    $tmp = $cachePath . '.tmp.' . getmypid();
    if (@file_put_contents($tmp, $body, LOCK_EX) !== false) @rename($tmp, $cachePath);
    return $data;
}

// ─── Full-Page Cache ─────────────────────────────────────────────────────────
function pageCacheGet($key) {
    if (function_exists('apcu_fetch')) {
        $ok = false; $entry = apcu_fetch('pc_' . $key, $ok); return $ok ? $entry : null;
    }
    $path = PAGE_CACHE_DIR . '/' . md5($key) . '.gz';
    if (!is_file($path) || (time() - filemtime($path)) >= PAGE_CACHE_TTL) return null;
    $raw = @file_get_contents($path);
    if ($raw === false || strlen($raw) < 2) return null;
    $etagLen = ord($raw[0]);
    if (strlen($raw) < 1 + $etagLen) return null;
    return ['etag' => substr($raw, 1, $etagLen), 'gz' => substr($raw, 1 + $etagLen)];
}

function pageCacheSet($key, $html) {
    $gz   = gzencode($html, 6);
    $etag = '"' . substr(md5($html), 0, 16) . '"';
    $entry = ['etag' => $etag, 'gz' => $gz];
    if (function_exists('apcu_store')) { apcu_store('pc_' . $key, $entry, PAGE_CACHE_TTL); return $entry; }
    if (!is_dir(PAGE_CACHE_DIR)) @mkdir(PAGE_CACHE_DIR, 0755, true);
    if (mt_rand(1, 100) === 1) {
        $files = glob(PAGE_CACHE_DIR . '/*.gz') ?: [];
        if (count($files) > PAGE_CACHE_MAX_FILES) {
            usort($files, function ($a, $b) { return filemtime($a) <=> filemtime($b); });
            foreach (array_slice($files, 0, count($files) - PAGE_CACHE_MAX_FILES) as $f) @unlink($f);
        }
    }
    $path = PAGE_CACHE_DIR . '/' . md5($key) . '.gz';
    $tmp  = $path . '.tmp.' . getmypid();
    if (@file_put_contents($tmp, chr(strlen($etag)) . $etag . $gz, LOCK_EX) !== false) @rename($tmp, $path);
    return $entry;
}

function sendCachedPage($entry, $cacheControl, $contentType = 'text/html; charset=UTF-8') {
    header('Content-Type: ' . $contentType);
    header('Cache-Control: ' . $cacheControl);
    header('ETag: ' . $entry['etag']);
    header('Vary: Accept-Encoding');
    $inm = trim($_SERVER['HTTP_IF_NONE_MATCH'] ?? '');
    if ($inm !== '' && $inm === $entry['etag']) { http_response_code(304); exit; }
    if (strpos($_SERVER['HTTP_ACCEPT_ENCODING'] ?? '', 'gzip') !== false) { header('Content-Encoding: gzip'); echo $entry['gz']; } else { echo gzdecode($entry['gz']); }
    exit;
}

function renderCached($key, $cacheControl, callable $render, $contentType = 'text/html; charset=UTF-8') {
    $cached = pageCacheGet($key);
    if ($cached) sendCachedPage($cached, $cacheControl, $contentType);
    ob_start();
    $render();
    $html = ob_get_clean();
    sendCachedPage(pageCacheSet($key, $html), $cacheControl, $contentType);
}

// ─── Data Accessors ─────────────────────────────────────────────────────────
function normalizeJob($j) {
    if (is_array($j) && !isset($j['ID']) && isset($j['id'])) $j['ID'] = $j['id'];
    return $j;
}
function normalizeJobs($jobs) { return is_array($jobs) ? array_map('normalizeJob', $jobs) : $jobs; }

function fmtJobCount($n) {
    // Round down to nearest 50K and show as "600K+" — never reveals exact count
    $rounded = floor($n / 50000) * 50000;
    if ($rounded >= 1000) return number_format($rounded / 1000) . 'K+';
    return number_format($rounded) . '+';
}

function getTotalJobs() {
    $data = apiGet('/api/jobs?page=1', API_TTL_INFO);
    return ($data && isset($data['pagination']['totalJobs'])) ? (int)$data['pagination']['totalJobs'] : 0;
}

function getJobsPage($page = 1, $limit = JOBS_PER_PAGE) {
    $page = max(1, (int)$page);
    $data = apiGet("/api/jobs?page={$page}", API_TTL_LIST);
    return ($data && isset($data['jobs']) && is_array($data['jobs'])) ? sanitizeJobTitles(normalizeJobs($data['jobs'])) : [];
}

function searchJobs($query, $page = 1, $limit = JOBS_PER_PAGE) {
    $page = max(1, (int)$page);
    $q = rawurlencode($query);
    $data = apiGet("/api/jobs?search={$q}&page={$page}", API_TTL_LIST);
    if (is_array($data) && isset($data['jobs'])) $data['jobs'] = sanitizeJobTitles(normalizeJobs($data['jobs']));
    return $data;
}

function getJobBySlug($slug) {
    $data = apiGet('/api/jobs/slug/' . rawurlencode($slug), API_TTL_JOB);
    if (!$data || empty($data['job'])) return null;
    $data['job'] = normalizeJob($data['job']);
    if (isset($data['job']['post_title'])) $data['job']['post_title'] = brandReplace($data['job']['post_title']);
    if (isset($data['recentJobs'])) $data['recentJobs'] = sanitizeJobTitles(normalizeJobs($data['recentJobs']));
    if (isset($data['randomJobs'])) $data['randomJobs'] = sanitizeJobTitles(normalizeJobs($data['randomJobs']));
    return $data;
}

// ─── Sitemap ─────────────────────────────────────────────────────────────────
define('SITEMAP_LINES_FILE', CACHE_DIR . '/sitemap_lines.txt');
define('SITEMAP_LOCK_FILE', CACHE_DIR . '/sitemap_build.lock');
define('SITEMAP_TTL', 3600);

function _extractSitemapChunk($buf, $out, &$count, $isFinal = false) {
    if ($buf === '') return '';
    if (!$isFinal) {
        $lastSlugPos = strrpos($buf, '"slug":"');
        $processEnd = $lastSlugPos !== false ? $lastSlugPos : strlen($buf);
        $toProcess  = substr($buf, 0, $processEnd);
        $remainder  = substr($buf, $processEnd);
    } else { $toProcess = $buf; $remainder = ''; }
    $parts = explode('"slug":"', $toProcess);
    array_shift($parts);
    foreach ($parts as $p) {
        $slugEnd = strpos($p, '"'); if ($slugEnd === false) continue;
        $slug = substr($p, 0, $slugEnd);
        $dateStart = strpos($p, '"post_date":"', $slugEnd); if ($dateStart === false) continue;
        $dateStart += 13; $dateEnd = strpos($p, '"', $dateStart); if ($dateEnd === false) continue;
        $date = substr($p, $dateStart, $dateEnd - $dateStart);
        if ($slug === '' || strlen($slug) > 200) continue;
        fwrite($out, $slug . "\t" . $date . "\n"); $count++;
    }
    return $remainder;
}

function buildSitemapLines() {
    @ini_set('memory_limit', '384M');
    if (!function_exists('curl_init')) { error_log('[sitemap] ext-curl not available'); return false; }
    if (!is_dir(CACHE_DIR)) @mkdir(CACHE_DIR, 0755, true);
    $tmp = SITEMAP_LINES_FILE . '.tmp.' . getmypid();
    $out = @fopen($tmp, 'w');
    if (!$out) { error_log("[sitemap] could not open tmp file: {$tmp}"); return false; }
    $headers = ['Accept: application/json'];
    if (API_KEY !== '') $headers[] = 'X-Api-Key: ' . API_KEY;
    $count = 0; $carry = '';
    $ch = curl_init(API_BASE . '/api/sitemap-jobs');
    curl_setopt_array($ch, [CURLOPT_TIMEOUT => 180, CURLOPT_CONNECTTIMEOUT => 10, CURLOPT_FOLLOWLOCATION => true, CURLOPT_HTTPHEADER => $headers, CURLOPT_WRITEFUNCTION => function ($ch, $chunk) use ($out, &$count, &$carry) { $carry = _extractSitemapChunk($carry . $chunk, $out, $count, false); return strlen($chunk); }]);
    $ok = curl_exec($ch); $code = curl_getinfo($ch, CURLINFO_HTTP_CODE); $err = curl_error($ch); curl_close($ch);
    if (!$ok || $code !== 200) { error_log("[sitemap] fetch failed: http_code={$code} curl_error=\"{$err}\""); fclose($out); @unlink($tmp); return false; }
    _extractSitemapChunk($carry, $out, $count, true);
    fclose($out);
    if ($count === 0) { error_log('[sitemap] 0 job lines extracted'); @unlink($tmp); return false; }
    @rename($tmp, SITEMAP_LINES_FILE);
    return $count;
}

function ensureSitemapLines() {
    $fresh = is_file(SITEMAP_LINES_FILE) && (time() - filemtime(SITEMAP_LINES_FILE)) < SITEMAP_TTL;
    if ($fresh) return true;
    if (!is_dir(CACHE_DIR)) @mkdir(CACHE_DIR, 0755, true);
    $lock = @fopen(SITEMAP_LOCK_FILE, 'c');
    if ($lock && flock($lock, LOCK_EX | LOCK_NB)) { buildSitemapLines(); flock($lock, LOCK_UN); fclose($lock); }
    elseif ($lock) { fclose($lock); }
    return is_file(SITEMAP_LINES_FILE);
}

function getSitemapPage($page, $limit) {
    if (!ensureSitemapLines()) return ['jobs' => []];
    $offset = ($page - 1) * $limit;
    $fh = @fopen(SITEMAP_LINES_FILE, 'r');
    if (!$fh) return ['jobs' => []];
    for ($i = 0; $i < $offset; $i++) { if (fgets($fh) === false) { fclose($fh); return ['jobs' => []]; } }
    $jobs = [];
    for ($i = 0; $i < $limit; $i++) {
        $line = fgets($fh); if ($line === false) break;
        $tab = strpos($line, "\t"); if ($tab === false) continue;
        $jobs[] = ['slug' => substr($line, 0, $tab), 'post_date' => rtrim(substr($line, $tab + 1))];
    }
    fclose($fh);
    return ['jobs' => $jobs];
}

// ─── Templates: HTML Head ────────────────────────────────────────────────────
function htmlHead($title, $desc = '', $canonical = '', $extra = '') {
    global $siteName, $companyName, $baseUrl, $metaDesc, $metaKeywords, $metaAuthor, $ogTitle, $ogDesc, $faviconSvg, $faviconBg;
    if (!$desc) $desc = $metaDesc;
    if (!$canonical) $canonical = $baseUrl;
    return '<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>' . e($title) . '</title>
<meta name="description" content="' . e($desc) . '">
<meta name="keywords" content="' . e($metaKeywords) . '">
<meta name="robots" content="index, follow, max-image-preview:large">
<meta name="author" content="' . e($metaAuthor) . '">
<meta property="og:title" content="' . e($ogTitle ?: $title) . '">
<meta property="og:description" content="' . e($ogDesc ?: $desc) . '">
<meta property="og:type" content="website">
<meta property="og:url" content="' . e($canonical) . '">
<meta property="og:site_name" content="' . e($companyName) . '">
<meta property="og:image" content="' . e($baseUrl) . '/work-from-home-jobs-image.webp">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="' . e($ogTitle ?: $title) . '">
<meta name="twitter:description" content="' . e($ogDesc ?: $desc) . '">
<link rel="icon" href="' . $faviconSvg . '">
<link rel="canonical" href="' . e($canonical) . '">
<meta name="theme-color" content="' . e($faviconBg) . '">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
' . inlineCSS() . '
' . $extra . '
</head>';
}

// ─── Template: Navbar ────────────────────────────────────────────────────────
function navbarHome() {
    global $companyName, $logoLetter;
    return '<div class="topbar">Discover thousands of remote opportunities — updated every day</div>
<nav>
    <div class="nav-container">
        <a href="/" class="logo"><span class="logo-mark">' . e($logoLetter) . '</span>' . e($companyName) . '</a>
        <div class="nav-links">
            <a href="/search" class="nav-link"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>Search</a>
            <a href="/remote-customer-service-jobs" class="nav-link">Browse Jobs</a>
        </div>
    </div>
</nav>';
}

function navbarDetail() {
    global $companyName, $logoLetter;
    return '<nav class="navbar">
    <div class="nav-container">
        <a href="/" class="nav-logo"><span class="logo-mark">' . e($logoLetter) . '</span>' . e($companyName) . '</a>
        <div class="nav-links">
            <a href="/" class="nav-link"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9,22 9,12 15,12 15,22"/></svg>Home</a>
            <a href="/search" class="nav-link"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>Search</a>
        </div>
    </div>
</nav>';
}

// ─── Template: Footer ────────────────────────────────────────────────────────
function siteFooter() {
    global $companyName, $logoLetter, $year, $sidebarStat1Num, $sidebarStat1Lbl, $sidebarStat2Num, $sidebarStat2Lbl, $JOB_CATEGORIES;
    $cats = array_slice($JOB_CATEGORIES, 0, 6);
    $catLinks = '';
    foreach ($cats as $cat) {
        $catLinks .= '<a href="' . catUrl($cat) . '">' . e(catLabel($cat)) . '</a>';
    }
    return '<footer class="footer">
    <div class="footer-grid">
        <div>
            <div class="footer-brand-logo"><span class="footer-mark">' . e($logoLetter) . '</span>' . e($companyName) . '</div>
            <p class="footer-desc">Your gateway to thousands of remote roles across every industry. New listings every single day.</p>
            <div class="footer-stats">
                <div><span class="footer-stat-num">' . e($sidebarStat1Num) . '</span><span class="footer-stat-lbl">' . e($sidebarStat1Lbl) . '</span></div>
                <div><span class="footer-stat-num">' . e($sidebarStat2Num) . '</span><span class="footer-stat-lbl">' . e($sidebarStat2Lbl) . '</span></div>
            </div>
        </div>
        <div>
            <div class="footer-col-title">Top Categories</div>
            <div class="footer-links-list">' . $catLinks . '</div>
        </div>
        <div>
            <div class="footer-col-title">Platform</div>
            <div class="footer-links-list">
                <a href="/">Home</a>
                <a href="/search">Search Jobs</a>
                <a href="/sitemap.xml">Sitemap</a>
                <a href="/robots.txt">Robots.txt</a>
            </div>
        </div>
        <div>
            <div class="footer-col-title">Popular Searches</div>
            <div class="footer-links-list">
                <a href="/remote-data-entry-jobs">Data Entry Jobs</a>
                <a href="/remote-chat-support-jobs">Chat Support Jobs</a>
                <a href="/remote-sales-jobs">Sales Jobs</a>
                <a href="/remote-healthcare-jobs">Healthcare Jobs</a>
                <a href="/remote-finance-jobs">Finance Jobs</a>
            </div>
        </div>
    </div>
    <div class="footer-bottom">
        <span class="footer-copy">&copy; ' . $year . ' ' . e($companyName) . '. All rights reserved.</span>
        <span class="footer-copy">Remote jobs updated daily.</span>
    </div>
</footer>';
}

// ─── Template: Job Card ──────────────────────────────────────────────────────
function jobCardHtml($job, $animate = false, $index = 0) {
    $title   = $job['post_title'] ?? '';
    $letter  = e(strtoupper(substr(trim((string)$title), 0, 1) ?: '?'));
    $posted  = isset($job['ID']) ? getJobDateLabel($job['ID']) : '';
    $isNew   = isset($job['ID']) && (abs(crc32((string)$job['ID'])) % 4 === 0);
    $cls     = 'job-card' . ($isNew ? ' job-card-new' : '') . ($animate ? ' fade-in-up' : '');
    $style   = $animate ? ' style="animation-delay:' . round($index * 0.06, 2) . 's"' : '';
    return '<article class="' . $cls . '"' . $style . '>
        ' . ($isNew ? '<span class="job-new-badge">&#10022; New</span>' : '') . '
        <div class="job-card-top">
            <div class="job-co-initial" aria-hidden="true">' . $letter . '</div>
            <div class="job-card-meta">
                <div class="job-co-name">Remote Opportunity</div>
                <h3 class="job-title"><a href="/remote-jobs/' . e($job['slug'] ?? '') . '">' . e($title) . '</a></h3>
            </div>
        </div>
        <div class="job-card-tags">
            <span class="tag tag-remote">Remote</span>
            <span class="tag tag-time">Full-time</span>
        </div>
        <div class="job-card-footer">
            <span class="job-posted">' . ($posted !== '' ? e($posted) : '') . '</span>
            <span class="job-arrow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12,5 19,12 12,19"/></svg></span>
        </div>
    </article>';
}

// ─── Route: Home / Pagination ────────────────────────────────────────────────
function renderHomePage($page) {
    global $siteName, $companyName, $baseUrl, $heroTitle, $tagline, $year, $JOB_CATEGORIES;
    global $sidebarStat1Num, $sidebarStat1Lbl, $sidebarStat2Num, $sidebarStat2Lbl;

    $totalJobs  = getTotalJobs();
    $totalPages = max(1, (int)ceil($totalJobs / JOBS_PER_PAGE));
    $page       = max(1, min((int)$page, $totalPages));
    $isHome     = ($page === 1);
    $pageJobs   = getJobsPage($page, JOBS_PER_PAGE);
    if ($isHome) shuffle($pageJobs);

    $extra = '';
    if ($page > 1) $extra .= '<link rel="prev" href="' . ($page === 2 ? '/' : '/page/' . ($page - 1)) . '">';
    if ($page < $totalPages) $extra .= '<link rel="next" href="/page/' . ($page + 1) . '">';

    $title     = $isHome ? e($companyName) . " — Remote Jobs, Work From Anywhere" : "Remote Jobs — Page {$page} | " . e($companyName);
    $canonical = $isHome ? $baseUrl : "{$baseUrl}/page/{$page}";

    echo htmlHead($title, '', $canonical, $extra);
    echo '<body>';
    echo navbarHome();
    echo '<main>';

    if ($isHome) {
        // ── Hero
        echo '<section class="hero">
    <div class="hero-inner">
        <div>
            <div class="hero-eyebrow"><span class="hero-eyebrow-dot"></span>' . fmtJobCount($totalJobs) . ' open positions today</div>
            <h1>' . $heroTitle . '</h1>
            <p class="hero-sub">' . e($tagline) . ' — find curated remote roles across every industry, refreshed daily.</p>
            <form action="/search" method="GET" class="hero-search">
                <input type="search" name="q" placeholder="Job title, skill, or keyword&hellip;" aria-label="Search jobs">
                <button type="submit" class="hero-search-btn"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>Find Jobs</button>
            </form>
            <div class="hero-trust">
                <span class="hero-trust-item"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>No account required</span>
                <span class="hero-trust-item"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>Updated daily</span>
                <span class="hero-trust-item"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>100% remote</span>
            </div>
        </div>
        <div class="hero-panel">
            <div class="hero-panel-title">Live stats</div>
            <div class="hero-stat-row">
                <div class="hero-stat-card">
                    <div class="hero-stat-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/></svg></div>
                    <div><div class="hero-stat-num">' . e($sidebarStat1Num) . '</div><div class="hero-stat-lbl">' . e($sidebarStat1Lbl) . '</div></div>
                </div>
                <div class="hero-stat-card">
                    <div class="hero-stat-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12,6 12,12 16,14"/></svg></div>
                    <div><div class="hero-stat-num">' . e($sidebarStat2Num) . '</div><div class="hero-stat-lbl">' . e($sidebarStat2Lbl) . '</div></div>
                </div>
                <div class="hero-stat-card">
                    <div class="hero-stat-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg></div>
                    <div><div class="hero-stat-num">' . fmtJobCount($totalJobs) . '</div><div class="hero-stat-lbl">Live Listings</div></div>
                </div>
            </div>
        </div>
    </div>
</section>';

        // ── Category Grid
        echo '<section class="categories">
    <div class="section-label">Explore by Category</div>
    <div class="section-heading">Popular Remote Job Types</div>
    <div class="cat-grid">';
        foreach (array_slice($JOB_CATEGORIES, 0, 10) as $cat) {
            echo '<a href="' . catUrl($cat) . '" class="cat-card"><span class="cat-icon">' . catEmoji($cat) . '</span>' . e(catLabel($cat)) . '</a>';
        }
        echo '</div></section>';
    }

    // ── Job Listings
    echo '<section class="jobs-section" id="jobs">
    <div class="jobs-header">
        <h2 class="jobs-title">' . ($isHome ? 'Latest Remote Opportunities' : "Remote Jobs &mdash; Page {$page}") . '</h2>
        <span class="jobs-count">' . fmtJobCount($totalJobs) . ' open roles</span>
    </div>
    <div class="jobs-grid">';

    foreach ($pageJobs as $job) {
        echo jobCardHtml($job);
    }

    echo '</div>';

    // Pagination
    echo '<div class="pagination">';
    if ($page > 1) {
        $prevUrl = $page === 2 ? '/' : '/page/' . ($page - 1);
        echo '<a href="' . $prevUrl . '" class="pagination-btn">&larr; Previous</a>';
    }
    echo '<span class="pagination-info">Page ' . $page . ' of ' . number_format($totalPages) . '</span>';
    if ($page < $totalPages) {
        echo '<a href="/page/' . ($page + 1) . '" class="pagination-btn">Next &rarr;</a>';
    }
    echo '</div></section>';

    if ($isHome) {
        // SEO content block
        echo '<section class="seo-block">
    <div class="seo-block-inner">
        <h2>Your Remote Career Starts Here</h2>
        <p>The remote work landscape has never offered more opportunity. From entry-level customer service roles to senior software engineers, companies worldwide are hiring fully distributed teams — meaning your next great job doesn\'t depend on where you live.</p>
        <p>On ' . e($companyName) . ', you\'ll find listings across <a href="' . catUrl($JOB_CATEGORIES[0]) . '">customer service</a>, <a href="' . catUrl($JOB_CATEGORIES[3]) . '">software development</a>, <a href="' . catUrl($JOB_CATEGORIES[2]) . '">virtual assistant</a>, <a href="' . catUrl($JOB_CATEGORIES[1]) . '">data entry</a>, and dozens of other categories — all refreshed daily so you\'re never applying to stale listings.</p>
        <p>Remote interviews are usually conducted over video, so test your setup beforehand. Highlight asynchronous communication and self-management skills on your application — they matter more in a distributed team than they do in an office environment.</p>
    </div>
</section>';

        // Second batch
        $morePage = getJobsPage(2, JOBS_PER_PAGE);
        if ($morePage) {
            echo '<section class="jobs-section" id="more-jobs">
    <div class="jobs-header">
        <h2 class="jobs-title">More Opportunities</h2>
        <span class="jobs-count">' . fmtJobCount($totalJobs) . ' total roles</span>
    </div>
    <div class="jobs-grid">';
            foreach ($morePage as $job) { echo jobCardHtml($job); }
            echo '</div>
    <div class="pagination"><a href="/page/2" class="pagination-btn">Browse More Jobs &rarr;</a></div>
</section>';
        }

        // All categories
        echo '<section class="categories" style="margin-top:1rem">
    <div class="section-label">All Categories</div>
    <div class="cat-grid">';
        foreach ($JOB_CATEGORIES as $cat) {
            echo '<a href="' . catUrl($cat) . '" class="cat-card"><span class="cat-icon">' . catEmoji($cat) . '</span>' . e(catLabel($cat)) . '</a>';
        }
        echo '</div></section>';
    }

    echo '</main>';
    echo siteFooter();
    echo '</body></html>';
}

// ─── Route: Job Detail ───────────────────────────────────────────────────────
function renderJobPage($slug) {
    global $siteName, $companyName, $baseUrl, $metaAuthor, $year;

    $result = getJobBySlug($slug);
    if (!$result) {
        $pool  = getJobsPage(1);
        $slugs = [];
        foreach ($pool as $j) { $s = $j['slug'] ?? ''; if ($s !== '' && $s !== $slug) $slugs[] = $s; }
        if ($slugs) { header('Location: ' . ($baseUrl !== '' ? $baseUrl : '') . '/remote-jobs/' . rawurlencode($slugs[array_rand($slugs)]), true, 301); }
        else { header('Location: ' . ($baseUrl !== '' ? $baseUrl . '/' : '/'), true, 301); }
        exit;
    }

    $job            = $result['job'];
    $content        = brandReplace($job['post_content'] ?? '');
    $permalink      = applyUrl($job['permalink'] ?? '');
    $jobImage       = getJobImage($job['post_title'], $job['slug']);
    $country        = jobCountry(intval($job['ID']));
    $today          = date('Y-m-d');
    $postedDate     = getJobDate($job['ID']);
    $postedLabel    = getJobDateLabel($job['ID']);
    $validThrough   = date('Y-m-d', strtotime('+30 days'));
    $formattedContent = formatJobContent($content);
    $similarJobs    = array_merge($result['recentJobs'] ?? [], $result['randomJobs'] ?? []);
    shuffle($similarJobs);

    $schema1 = json_encode([
        '@context' => 'https://schema.org', '@type' => 'JobPosting',
        'title' => $job['post_title'], 'datePosted' => $postedDate, 'validThrough' => $validThrough,
        'description' => safeSubstr($content, 5000),
        'url' => "{$baseUrl}/remote-jobs/{$slug}",
        'jobLocationType' => 'TELECOMMUTE',
        'applicantLocationRequirements' => ['@type' => 'Country', 'name' => 'Worldwide'],
        'employmentType' => 'FULL_TIME',
        'hiringOrganization' => ['@type' => 'Organization', 'name' => $companyName, 'sameAs' => $baseUrl],
        'jobLocation' => ['@type' => 'Place', 'address' => ['@type' => 'PostalAddress', 'addressCountry' => $country['iso']]],
    ], JSON_UNESCAPED_SLASHES);

    $schema2 = json_encode([
        '@context' => 'https://schema.org', '@type' => 'BreadcrumbList',
        'itemListElement' => [
            ['@type' => 'ListItem', 'position' => 1, 'name' => 'Home', 'item' => $baseUrl],
            ['@type' => 'ListItem', 'position' => 2, 'name' => $job['post_title'], 'item' => "{$baseUrl}/remote-jobs/{$slug}"],
        ],
    ], JSON_UNESCAPED_SLASHES);

    $extra = '<script type="application/ld+json">' . $schema1 . '</script>
<script type="application/ld+json">' . $schema2 . '</script>';

    echo htmlHead(
        e($job['post_title']) . ' — ' . $siteName,
        e(safeSubstr(strip_tags($content), 155)) . '...',
        "{$baseUrl}/remote-jobs/{$slug}",
        '<meta property="og:title" content="' . e($job['post_title']) . ' — ' . e($siteName) . '">
<meta property="og:description" content="' . e(safeSubstr($content, 160)) . '...">
<meta property="og:type" content="article">
<meta property="og:image" content="' . e($baseUrl) . '/' . e($jobImage) . '">
<meta property="article:published_time" content="' . $today . '">
' . $extra
    );

    $jobLetter = e(strtoupper(substr(trim((string)$job['post_title']), 0, 1) ?: '?'));

    echo '<body>';
    echo navbarDetail();
    echo '<nav class="breadcrumb" aria-label="Breadcrumb">
    <a href="/">Home</a>
    <span class="breadcrumb-sep"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9,6 15,12 9,18"/></svg></span>
    <span class="breadcrumb-current">' . e($job['post_title']) . '</span>
</nav>';

    echo '<main><div class="detail-wrap">
    <a href="/" class="back-btn"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="19" y1="12" x2="5" y2="12"/><polyline points="12,19 5,12 12,5"/></svg>Back to Jobs</a>
    <div class="detail-main">
        <div class="detail-header">
            <div class="detail-header-top">
                <div class="detail-avatar" aria-hidden="true">' . $jobLetter . '</div>
                <div>
                    <h1 class="detail-title">' . e($job['post_title']) . '</h1>
                    <div class="detail-tags">
                        <span class="tag tag-remote"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg>Remote &bull; ' . e($country['name']) . '</span>
                        <span class="tag tag-time">Full-time</span>
                        <span class="tag">Posted ' . e($postedLabel) . '</span>
                    </div>
                </div>
            </div>
        </div>
        <div class="detail-body">
            <div class="job-content">' . $formattedContent . '</div>
            <div class="detail-apply-footer">
                <a href="' . e($permalink) . '" class="apply-btn" rel="nofollow noopener" target="_blank">Apply for This Role &rarr;</a>
            </div>
        </div>
    </div>';

    if ($similarJobs) {
        echo '<div class="related-section">
        <div class="jobs-header">
            <h2 class="jobs-title">Similar Remote Jobs</h2>
        </div>
        <div class="related-grid">';
        foreach ($similarJobs as $i => $sj) {
            echo jobCardHtml($sj, true, $i);
        }
        echo '</div></div>';
    }

    echo '</div></main>';
    echo siteFooter();
    echo '</body></html>';
}

// ─── Helper: category URL ────────────────────────────────────────────────────
function categoryUrl($keyword) {
    $slug = strtolower(trim($keyword));
    $slug = preg_replace('/\s+/', '-', $slug);
    $slug = preg_replace('/[^a-z0-9-]/', '', $slug);
    $slug = preg_replace('/-+/', '-', $slug);
    return '/remote-' . $slug . '-jobs';
}

// ─── Route: Search ───────────────────────────────────────────────────────────
function renderSearch() {
    global $baseUrl;
    $q = isset($_GET['q']) ? trim($_GET['q']) : '';
    if ($q !== '') { header('Location: ' . $baseUrl . categoryUrl($q), true, 301); exit; }
    renderCategoryPage('', '');
}

// ─── Route: Category ─────────────────────────────────────────────────────────
function renderCategoryPage($keyword, $cleanSlug, $page = 1) {
    global $siteName, $companyName, $baseUrl;

    $q    = $keyword;
    $page = max(1, (int)$page);
    $results      = [];
    $totalResults = 0;
    $totalPages   = 1;

    if (strlen($q) >= 2) {
        $data = searchJobs($q, $page, JOBS_PER_PAGE);
        if ($data && !empty($data['jobs'])) {
            $results      = $data['jobs'];
            $totalResults = (int)($data['pagination']['totalJobs'] ?? count($results));
            $totalPages   = (int)($data['pagination']['totalPages'] ?? 1);
        }
    }

    $displayName = ucwords($q);
    $basePath    = $q ? categoryUrl($q) : '/search';
    $canonical   = $baseUrl . ($page > 1 ? "{$basePath}/page/{$page}" : $basePath);
    $pageTitle   = $q
        ? ($page > 1
            ? "Remote {$displayName} Jobs — Page {$page} | {$companyName}"
            : "Remote {$displayName} Jobs — Work From Home | {$companyName}")
        : "Search Remote Jobs | {$siteName}";
    $pageDesc = $q
        ? "Browse {$totalResults} remote {$displayName} jobs on {$companyName}. Find work-from-home {$displayName} positions worldwide — apply with no account required."
        : "Search remote jobs by keyword on {$companyName}.";

    $extra = '';
    if ($page > 1)           $extra .= '<link rel="prev" href="' . ($page === 2 ? $basePath : "{$basePath}/page/" . ($page - 1)) . '">';
    if ($page < $totalPages) $extra .= '<link rel="next" href="' . "{$basePath}/page/" . ($page + 1) . '">';

    echo htmlHead($pageTitle, $pageDesc, $canonical, $extra);
    echo '<body>';
    echo navbarDetail();

    if ($q) {
        echo '<nav class="breadcrumb" aria-label="Breadcrumb">
    <a href="/">Home</a>
    <span class="breadcrumb-sep"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9,6 15,12 9,18"/></svg></span>
    <span class="breadcrumb-current">Remote ' . e($displayName) . ' Jobs</span>
</nav>';
    }

    echo '<section class="search-hero">
    <div class="search-hero-inner">
        <h1>' . ($q ? 'Remote <em>' . e($displayName) . '</em> Jobs' : 'Search Jobs') . '</h1>
        <form action="/search" method="GET" class="hero-search" style="max-width:480px;margin-top:1rem">
            <input type="search" name="q" placeholder="Search remote jobs&hellip;" value="' . e($q) . '" aria-label="Search jobs">
            <button type="submit" class="hero-search-btn"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>Search</button>
        </form>
    </div>
</section>

<main><section class="jobs-section" id="jobs">
    <div class="jobs-header">
        <h2 class="jobs-title">' . ($q
            ? fmtJobCount($totalResults) . ' Remote ' . e($displayName) . ' Jobs' . ($page > 1 ? " — Page {$page}" : '')
            : 'Enter a search term') . '</h2>
    </div>
    <div class="jobs-grid">';

    if (count($results) > 0) {
        foreach ($results as $r) { echo jobCardHtml($r); }
    } elseif ($q) {
        echo '<div class="empty-state">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            <p>No results for &ldquo;' . e($q) . '&rdquo;. Try different keywords.</p>
            <a href="/">&larr; Browse all jobs</a>
        </div>';
    }

    echo '</div>';

    if ($q && $totalPages > 1) {
        echo '<div class="pagination">';
        if ($page > 1) { $prev = $page === 2 ? $basePath : "{$basePath}/page/" . ($page - 1); echo '<a href="' . $prev . '" class="pagination-btn">&larr; Previous</a>'; }
        echo '<span class="pagination-info">Page ' . $page . ' of ' . number_format($totalPages) . '</span>';
        if ($page < $totalPages) { echo '<a href="' . "{$basePath}/page/" . ($page + 1) . '" class="pagination-btn">Next &rarr;</a>'; }
        echo '</div>';
    }

    echo '</section></main>';
    echo siteFooter();
    echo '</body></html>';
}

// ─── Route: Sitemap ──────────────────────────────────────────────────────────
function renderSitemap($type, $id) {
    global $baseUrl;
    header('X-Robots-Tag: noindex');
    $totalJobs = getTotalJobs();
    if (!$totalJobs) { echo '<?xml version="1.0" encoding="UTF-8"?><error>Upstream API unavailable.</error>'; return; }
    $totalSitemaps = (int)ceil($totalJobs / URLS_PER_SITEMAP);
    $today = date('Y-m-d');
    if ($type === 'index') {
        echo '<?xml version="1.0" encoding="UTF-8"?>' . "\n<sitemapindex xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n";
        for ($i = 1; $i <= $totalSitemaps; $i++) echo "    <sitemap><loc>{$baseUrl}/sitemap-jobs{$i}.xml</loc><lastmod>{$today}</lastmod></sitemap>\n";
        echo '</sitemapindex>';
    } elseif ($id >= 1 && $id <= $totalSitemaps) {
        $data = getSitemapPage($id, URLS_PER_SITEMAP);
        $jobs = ($data && isset($data['jobs'])) ? $data['jobs'] : [];
        echo '<?xml version="1.0" encoding="UTF-8"?>' . "\n<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n";
        if ($id === 1) echo "    <url><loc>{$baseUrl}</loc><lastmod>{$today}</lastmod><changefreq>daily</changefreq><priority>1.0</priority></url>\n";
        foreach ($jobs as $j) {
            $slug = $j['post_name'] ?? $j['slug'] ?? '';
            if (!$slug || strlen($slug) > 200) continue;
            $lastmod = !empty($j['post_date']) ? substr($j['post_date'], 0, 10) : $today;
            echo "    <url><loc>{$baseUrl}/remote-jobs/{$slug}</loc><lastmod>{$lastmod}</lastmod><changefreq>daily</changefreq><priority>0.8</priority></url>\n";
        }
        echo '</urlset>';
    } else {
        http_response_code(404);
        echo '<?xml version="1.0" encoding="UTF-8"?><error>Not found</error>';
    }
}

// ─── Route: Robots.txt ───────────────────────────────────────────────────────
function renderRobots() {
    global $baseUrl, $GOOGLE_BOTS;
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: public, max-age=86400');
    $out = '';
    foreach ($GOOGLE_BOTS as $bot) { $out .= "User-agent: {$bot}\nAllow: /\n\n"; }
    $out .= "User-agent: *\nDisallow: /\n\n";
    $out .= "Sitemap: {$baseUrl}/sitemap.xml\n";
    echo $out;
}

// ─── Router ─────────────────────────────────────────────────────────────────
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$uri = rtrim($uri, '/');
if ($uri === '') $uri = '/';

const PAGE_CC = 'public, max-age=300, stale-while-revalidate=3600';

if ($uri === '/') {
    renderCached('home', PAGE_CC, function () { renderHomePage(1); });
}
elseif (preg_match('#^/page/(\d+)$#', $uri, $m)) {
    $p = intval($m[1]);
    renderCached("home:page:{$p}", PAGE_CC, function () use ($p) { renderHomePage($p); });
}
// Old job URL shape (/job/<slug>) → 301 to current shape (/remote-jobs/<slug>)
elseif (preg_match('#^/job/(.+)$#', $uri, $m)) {
    header('Location: ' . ($baseUrl !== '' ? $baseUrl : '') . '/remote-jobs/' . $m[1], true, 301);
    exit;
}
elseif (preg_match('#^/remote-jobs/(.+)$#', $uri, $m)) {
    $slug = urldecode($m[1]);
    renderCached("job:{$slug}", PAGE_CC, function () use ($slug) { renderJobPage($slug); });
}
elseif ($uri === '/search') {
    renderSearch();
}
elseif (preg_match('#^/remote-([a-z0-9-]+)-jobs$#', $uri, $m)) {
    $keyword = str_replace('-', ' ', $m[1]);
    $slug    = $m[1];
    renderCached("cat:{$slug}", PAGE_CC, function () use ($keyword, $slug) { renderCategoryPage($keyword, $slug, 1); });
}
elseif (preg_match('#^/remote-([a-z0-9-]+)-jobs/page/(\d+)$#', $uri, $m)) {
    $keyword = str_replace('-', ' ', $m[1]);
    $slug    = $m[1];
    $p       = intval($m[2]);
    renderCached("cat:{$slug}:page:{$p}", PAGE_CC, function () use ($keyword, $slug, $p) { renderCategoryPage($keyword, $slug, $p); });
}
elseif ($uri === '/sitemap.xml') {
    renderCached('sitemap:index', 'public, max-age=3600', function () { renderSitemap('index', 0); }, 'application/xml; charset=utf-8');
}
elseif (preg_match('#^/sitemap-jobs(\d+)\.xml$#', $uri, $m)) {
    $n = intval($m[1]);
    renderCached("sitemap:{$n}", 'public, max-age=3600', function () use ($n) { renderSitemap('', $n); }, 'application/xml; charset=utf-8');
}
elseif ($uri === '/robots.txt') {
    renderRobots();
}
elseif (preg_match('#^/(google[a-z0-9]+\.html)$#', $uri, $m) && is_file(__DIR__ . '/' . $m[1])) {
    header('Content-Type: text/html; charset=UTF-8');
    readfile(__DIR__ . '/' . $m[1]);
}
elseif (preg_match('#^/\.well-known/acme-challenge/([A-Za-z0-9_-]+)$#', $uri, $m)
        && is_file(__DIR__ . '/.well-known/acme-challenge/' . basename($m[1]))) {
    header('Content-Type: text/plain; charset=UTF-8');
    readfile(__DIR__ . '/.well-known/acme-challenge/' . basename($m[1]));
}
else {
    http_response_code(404);
    renderHomePage(1);
}
