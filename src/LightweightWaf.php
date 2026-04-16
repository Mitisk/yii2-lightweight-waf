<?php

declare(strict_types=1);

namespace Mitisk\Waf;

/**
 * Lightweight WAF (Web Application Firewall)
 * Предназначен для защиты от автоматических сканеров уязвимостей (dirsearch, wp-scanners и др.)
 * Работает на раннем этапе загрузки до инициализации тяжелого ядра Yii2.
 */
class LightweightWaf
{
    private const BANNED_IPS_FILE = 'banned_ips.json';
    private const BLOCK_PREFIX = 'block_';
    private const CAPTCHA_PREFIX = 'captcha_';

    /** @var array<string> Словарь плохих паттернов URI по умолчанию */
    private static array $badPatterns = [
        '/admin.php',
        '/manager.php',
        '/phpinfo.php',
        '/upload.php',
        '/init.php',
        '/install.php',
        '/local.php',
        '/login.php',
        '/mail.php',
        '/info.php',
        '/function.php',
        '/wp_cron.php',
        '.well-known',
        'wp-login',
        'wp-content',
        'wp-admin',
        'wp-cache',
        'wp-includes',
        '/xmlrpc.php',
        '/config.json',
        'phpunit',
        '.env',
        '/bitrix/admin',
        '.git',
    ];

    /** @var string Путь к директории хранения заблокированных IP */
    private static string $storageDir;

    /** @var string|null Секретный ключ Google reCAPTCHA v2 */
    private static ?string $recaptchaSecret = null;

    /** @var string|null Публичный ключ (Site Key) Google reCAPTCHA v2 */
    private static ?string $recaptchaSiteKey = null;

    /** @var int Время блокировки в секундах */
    private static int $blockDuration = 86400;

    /** @var bool Блокировать IP навсегда (хранить в одном файле banned_ips.json) */
    private static bool $permanentBlock = false;

    /** @var array<string> Доверенные заголовки для определения IP (пусто = только REMOTE_ADDR) */
    private static array $trustedHeaders = [];

    /** @var array<string> Доверенные прокси (IP или CIDR), от которых принимаются trustedHeaders */
    private static array $trustedProxies = [];

    /** @var int Максимум неудачных попыток каптчи в окне */
    private static int $captchaMaxAttempts = 5;

    /** @var int Длина окна попыток каптчи в секундах */
    private static int $captchaWindow = 600;

    /** @var array<string,true>|null Кеш map'ы перманентных банов на время запроса */
    private static ?array $bannedIpsCache = null;

    /**
     * Точка входа для WAF. Вызывается в web/index.php.
     *
     * @param array<string, mixed> $config Конфигурационные параметры:
     * - runtimePath (string, required): Путь до папки runtime
     * - recaptchaSiteKey (string, optional): Публичный ключ каптчи
     * - recaptchaSecret (string, optional): Приватный ключ каптчи
     * - badPatterns (array, optional): Массив уязвимых путей для блокировки
     * - blockDuration (int, optional): Время блокировки в секундах (по умолчанию 86400)
     * - permanentBlock (bool, optional): Блокировать навсегда (по умолчанию false)
     * - trustedHeaders (array, optional): Заголовки для определения IP за прокси
     * - trustedProxies (array, optional): IP или CIDR доверенных прокси, от которых принимаются trustedHeaders
     * - captchaMaxAttempts (int, optional): Максимум неудач каптчи в окне (по умолчанию 5)
     * - captchaWindow (int, optional): Длина окна попыток каптчи в секундах (по умолчанию 600)
     */
    public static function run(array $config): void
    {
        if (empty($config['runtimePath'])) {
            self::terminate('Configuration error.');
        }

        self::$storageDir = rtrim((string) $config['runtimePath'], '/\\') . DIRECTORY_SEPARATOR . 'waf_blocks';
        self::$recaptchaSiteKey = !empty($config['recaptchaSiteKey']) ? (string) $config['recaptchaSiteKey'] : null;
        self::$recaptchaSecret = !empty($config['recaptchaSecret']) ? (string) $config['recaptchaSecret'] : null;

        if (!empty($config['badPatterns']) && is_array($config['badPatterns'])) {
            self::$badPatterns = $config['badPatterns'];
        }
        if (isset($config['blockDuration'])) {
            self::$blockDuration = (int) $config['blockDuration'];
        }
        if (isset($config['permanentBlock'])) {
            self::$permanentBlock = (bool) $config['permanentBlock'];
        }
        if (!empty($config['trustedHeaders']) && is_array($config['trustedHeaders'])) {
            self::$trustedHeaders = $config['trustedHeaders'];
        }
        if (!empty($config['trustedProxies']) && is_array($config['trustedProxies'])) {
            self::$trustedProxies = array_values(array_filter($config['trustedProxies'], is_string(...)));
        }
        if (isset($config['captchaMaxAttempts'])) {
            self::$captchaMaxAttempts = max(1, (int) $config['captchaMaxAttempts']);
        }
        if (isset($config['captchaWindow'])) {
            self::$captchaWindow = max(1, (int) $config['captchaWindow']);
        }

        // 0. Очистка старых файлов блокировки и каптч-счётчиков (старше 2 дней).
        self::cleanupOldBlockFiles();

        $ip = self::getClientIp();
        $uri = $_SERVER['REQUEST_URI'] ?? '/';
        $blockFile = self::$permanentBlock
            ? null
            : self::$storageDir . DIRECTORY_SEPARATOR . self::BLOCK_PREFIX . md5($ip) . '.txt';

        // 1. Проверяем, находится ли IP в черном списке
        if (self::$permanentBlock) {
            if (self::isIpPermanentlyBanned($ip)) {
                self::handleBlockedRequest($ip, null, null);
                exit;
            }
        } elseif (file_exists($blockFile)) {
            $expireTime = (int) @file_get_contents($blockFile);
            if (time() < $expireTime) {
                self::handleBlockedRequest($ip, $blockFile, $expireTime);
                exit;
            }
            @unlink($blockFile);
        }

        // 2. Проверяем URI на совпадение с плохими паттернами
        $uriLower = strtolower($uri);
        foreach (self::$badPatterns as $pattern) {
            if (str_contains($uriLower, strtolower($pattern))) {
                if (self::$permanentBlock) {
                    self::addPermanentBan($ip);
                    self::handleBlockedRequest($ip, null, null);
                } else {
                    self::blockIp($blockFile);
                    self::handleBlockedRequest($ip, $blockFile, time() + self::$blockDuration);
                }
                exit;
            }
        }
    }

    /**
     * Удаляет файлы блокировки и каптч-счётчики, созданные более 2 дней назад.
     * Проверка выполняется с вероятностью 1/50, чтобы не сканировать директорию на каждый запрос.
     * В режиме permanentBlock блок-файлы не должны существовать, но каптч-счётчики чистим.
     */
    private static function cleanupOldBlockFiles(): void
    {
        if (mt_rand(1, 50) !== 1) {
            return;
        }

        if (!is_dir(self::$storageDir)) {
            return;
        }

        $threshold = time() - 2 * 86400;
        $files = @scandir(self::$storageDir);

        if ($files === false) {
            return;
        }

        $skipBlocks = self::$permanentBlock;

        foreach ($files as $file) {
            if (!str_ends_with($file, '.txt')) {
                continue;
            }

            $isBlock = !$skipBlocks && str_starts_with($file, self::BLOCK_PREFIX);
            $isCaptcha = str_starts_with($file, self::CAPTCHA_PREFIX);

            if (!$isBlock && !$isCaptcha) {
                continue;
            }

            $filePath = self::$storageDir . DIRECTORY_SEPARATOR . $file;

            if (is_file($filePath) && @filemtime($filePath) < $threshold) {
                @unlink($filePath);
            }
        }
    }

    /**
     * Блокирует IP-адрес путем создания файла с timestamp окончания блокировки.
     */
    private static function blockIp(string $blockFile): void
    {
        self::ensureStorageDir();
        @file_put_contents($blockFile, (string) (time() + self::$blockDuration), LOCK_EX);
    }

    /**
     * Создаёт директорию хранилища, если её ещё нет.
     */
    private static function ensureStorageDir(): void
    {
        if (!is_dir(self::$storageDir)) {
            @mkdir(self::$storageDir, 0755, true);
        }
    }

    /**
     * Возвращает путь к общему файлу перманентных банов.
     */
    private static function bannedIpsFile(): string
    {
        return self::$storageDir . DIRECTORY_SEPARATOR . self::BANNED_IPS_FILE;
    }

    /**
     * Загружает (с кешированием в рамках запроса) перманентные баны как map<ip, true>
     * для O(1)-проверки.
     *
     * @return array<string, true>
     */
    private static function loadBannedIpsMap(): array
    {
        if (self::$bannedIpsCache !== null) {
            return self::$bannedIpsCache;
        }

        $file = self::bannedIpsFile();
        if (!is_file($file)) {
            return self::$bannedIpsCache = [];
        }

        $handle = @fopen($file, 'rb');
        if ($handle === false) {
            return self::$bannedIpsCache = [];
        }

        $contents = '';
        if (flock($handle, LOCK_SH)) {
            while (!feof($handle)) {
                $chunk = fread($handle, 8192);
                if ($chunk === false) {
                    break;
                }
                $contents .= $chunk;
            }
            flock($handle, LOCK_UN);
        }
        fclose($handle);

        if ($contents === '') {
            return self::$bannedIpsCache = [];
        }

        $decoded = json_decode($contents, true);
        if (!is_array($decoded)) {
            return self::$bannedIpsCache = [];
        }

        $map = [];
        foreach ($decoded as $item) {
            if (is_string($item)) {
                $map[$item] = true;
            }
        }

        return self::$bannedIpsCache = $map;
    }

    /**
     * Атомарно обновляет список перманентных банов (read-modify-write под LOCK_EX).
     *
     * @param callable(array<string>): array<string> $mutator
     */
    private static function mutateBannedIps(callable $mutator): void
    {
        self::ensureStorageDir();
        $file = self::bannedIpsFile();

        $handle = @fopen($file, 'cb+');
        if ($handle === false) {
            return;
        }

        if (!flock($handle, LOCK_EX)) {
            fclose($handle);
            return;
        }

        $contents = '';
        while (!feof($handle)) {
            $chunk = fread($handle, 8192);
            if ($chunk === false) {
                break;
            }
            $contents .= $chunk;
        }

        $decoded = $contents !== '' ? json_decode($contents, true) : [];
        $ips = is_array($decoded) ? array_values(array_filter($decoded, is_string(...))) : [];

        $updated = $mutator($ips);
        $json = json_encode(array_values(array_unique($updated)), JSON_UNESCAPED_SLASHES);

        if ($json === false) {
            flock($handle, LOCK_UN);
            fclose($handle);
            return;
        }

        rewind($handle);
        ftruncate($handle, 0);
        fwrite($handle, $json);
        fflush($handle);
        flock($handle, LOCK_UN);
        fclose($handle);

        self::$bannedIpsCache = null;
    }

    /**
     * Проверяет, находится ли IP в списке перманентных банов.
     */
    private static function isIpPermanentlyBanned(string $ip): bool
    {
        return isset(self::loadBannedIpsMap()[$ip]);
    }

    /**
     * Добавляет IP в список перманентных банов.
     */
    private static function addPermanentBan(string $ip): void
    {
        self::mutateBannedIps(static function (array $ips) use ($ip): array {
            if (!in_array($ip, $ips, true)) {
                $ips[] = $ip;
            }
            return $ips;
        });
    }

    /**
     * Удаляет IP из списка перманентных банов.
     */
    private static function removePermanentBan(string $ip): void
    {
        self::mutateBannedIps(
            static fn (array $ips): array => array_values(
                array_filter($ips, static fn (string $item): bool => $item !== $ip)
            )
        );
    }

    /**
     * Обрабатывает заблокированный запрос: если настроена каптча и лимит попыток
     * не исчерпан — показывает форму, иначе выводит статичную страницу 403.
     */
    private static function handleBlockedRequest(string $ip, ?string $blockFile, ?int $expireTime): void
    {
        if (self::$recaptchaSiteKey === null || self::$recaptchaSecret === null) {
            self::renderBlockedPage($expireTime);
            return;
        }

        if (self::captchaAttemptsExceeded($ip)) {
            self::renderBlockedPage($expireTime);
            return;
        }

        $error = null;

        if (
            ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST'
            && !empty($_POST['g-recaptcha-response'])
        ) {
            if (self::verifyCaptcha($_POST['g-recaptcha-response'], $ip)) {
                self::clearCaptchaAttempts($ip);
                if (self::$permanentBlock) {
                    self::removePermanentBan($ip);
                } elseif ($blockFile !== null) {
                    @unlink($blockFile);
                }
                header('Location: /', true, 302);
                exit;
            }

            $remaining = self::recordCaptchaFailure($ip);
            if ($remaining <= 0) {
                self::renderBlockedPage($expireTime);
                return;
            }
            $error = 'Каптча не пройдена или устарела. Осталось попыток: ' . $remaining . '.';
        }

        self::renderCaptchaPage($error, $expireTime);
    }

    /**
     * Возвращает путь к файлу-счётчику попыток каптчи для IP.
     */
    private static function captchaFile(string $ip): string
    {
        return self::$storageDir . DIRECTORY_SEPARATOR . self::CAPTCHA_PREFIX . md5($ip) . '.txt';
    }

    /**
     * Читает текущее состояние счётчика попыток каптчи.
     *
     * @return array{0:int,1:int} [count, window_start_timestamp]
     */
    private static function loadCaptchaAttempts(string $ip): array
    {
        $file = self::captchaFile($ip);
        if (!is_file($file)) {
            return [0, 0];
        }

        $raw = (string) @file_get_contents($file);
        if ($raw === '' || !str_contains($raw, '|')) {
            return [0, 0];
        }

        $parts = explode('|', $raw, 2);
        return [(int) ($parts[0] ?? 0), (int) ($parts[1] ?? 0)];
    }

    /**
     * Проверяет, исчерпан ли лимит попыток каптчи для IP.
     * Если окно истекло — сбрасывает счётчик.
     */
    private static function captchaAttemptsExceeded(string $ip): bool
    {
        [$count, $start] = self::loadCaptchaAttempts($ip);
        if ($count < self::$captchaMaxAttempts) {
            return false;
        }
        if (time() - $start >= self::$captchaWindow) {
            @unlink(self::captchaFile($ip));
            return false;
        }
        return true;
    }

    /**
     * Записывает неудачную попытку каптчи. Возвращает оставшееся число попыток (>=0).
     */
    private static function recordCaptchaFailure(string $ip): int
    {
        self::ensureStorageDir();
        [$count, $start] = self::loadCaptchaAttempts($ip);
        $now = time();
        if ($start === 0 || $now - $start >= self::$captchaWindow) {
            $count = 0;
            $start = $now;
        }
        $count++;
        @file_put_contents(self::captchaFile($ip), $count . '|' . $start, LOCK_EX);
        return max(0, self::$captchaMaxAttempts - $count);
    }

    /**
     * Удаляет счётчик попыток каптчи для IP (после успешной верификации).
     */
    private static function clearCaptchaAttempts(string $ip): void
    {
        @unlink(self::captchaFile($ip));
    }

    /**
     * Валидация токена reCAPTCHA через API Google.
     */
    private static function verifyCaptcha(string $response, string $ip): bool
    {
        $body = self::httpPost(
            'https://www.google.com/recaptcha/api/siteverify',
            [
                'secret' => self::$recaptchaSecret,
                'response' => $response,
                'remoteip' => $ip,
            ],
            5
        );

        if ($body === null) {
            return false;
        }

        $json = json_decode($body, true);

        return !empty($json['success']);
    }

    /**
     * POST-запрос. Предпочитает cURL, fallback — stream context.
     * Возвращает тело ответа или null при ошибке/non-2xx.
     *
     * @param array<string, scalar|null> $data
     */
    private static function httpPost(string $url, array $data, int $timeout): ?string
    {
        $payload = http_build_query($data);

        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            if ($ch !== false) {
                curl_setopt_array($ch, [
                    CURLOPT_POST => true,
                    CURLOPT_POSTFIELDS => $payload,
                    CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_CONNECTTIMEOUT => $timeout,
                    CURLOPT_TIMEOUT => $timeout,
                    CURLOPT_HTTPHEADER => ['Content-Type: application/x-www-form-urlencoded'],
                ]);
                $result = curl_exec($ch);
                $code = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
                curl_close($ch);
                if (is_string($result) && $code >= 200 && $code < 300) {
                    return $result;
                }
            }
        }

        $context = stream_context_create([
            'http' => [
                'header' => "Content-Type: application/x-www-form-urlencoded\r\n",
                'method' => 'POST',
                'content' => $payload,
                'timeout' => $timeout,
                'ignore_errors' => true,
            ],
        ]);

        $result = @file_get_contents($url, false, $context);
        return is_string($result) ? $result : null;
    }

    /**
     * Получает реальный IP-адрес клиента.
     * По умолчанию использует только REMOTE_ADDR (защита от спуфинга).
     * Чтение из trustedHeaders разрешено только если REMOTE_ADDR входит в trustedProxies.
     */
    private static function getClientIp(): string
    {
        $remote = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';

        if (empty(self::$trustedHeaders)) {
            return $remote;
        }

        if (empty(self::$trustedProxies)) {
            self::warnTrustedHeadersWithoutProxies();
            return $remote;
        }

        if (!self::ipInCidrList($remote, self::$trustedProxies)) {
            return $remote;
        }

        foreach (self::$trustedHeaders as $header) {
            $key = 'HTTP_' . strtoupper(str_replace('-', '_', $header));
            if (!empty($_SERVER[$key])) {
                foreach (explode(',', $_SERVER[$key]) as $ip) {
                    $ip = trim($ip);
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
                        return $ip;
                    }
                }
            }
        }

        return $remote;
    }

    /**
     * Один раз за процесс пишет в error_log предупреждение о небезопасной конфигурации.
     */
    private static function warnTrustedHeadersWithoutProxies(): void
    {
        static $warned = false;
        if ($warned) {
            return;
        }
        $warned = true;
        @error_log('[LightweightWaf] trustedHeaders задан без trustedProxies — заголовки игнорируются для защиты от IP-спуфинга.');
    }

    /**
     * Проверяет, входит ли IP в любой из CIDR-диапазонов или совпадает с IP из списка.
     * Поддерживает IPv4 и IPv6.
     *
     * @param array<string> $cidrs
     */
    private static function ipInCidrList(string $ip, array $cidrs): bool
    {
        $ipBin = @inet_pton($ip);
        if ($ipBin === false) {
            return false;
        }
        $ipLen = strlen($ipBin);
        $maxMask = $ipLen * 8;

        foreach ($cidrs as $cidr) {
            if (str_contains($cidr, '/')) {
                [$subnet, $maskStr] = explode('/', $cidr, 2);
                $mask = (int) $maskStr;
            } else {
                $subnet = $cidr;
                $mask = $maxMask;
            }

            $subnetBin = @inet_pton($subnet);
            if ($subnetBin === false || strlen($subnetBin) !== $ipLen) {
                continue;
            }
            if ($mask < 0 || $mask > $maxMask) {
                continue;
            }

            $bytes = intdiv($mask, 8);
            $bits = $mask % 8;

            if ($bytes > 0 && substr($ipBin, 0, $bytes) !== substr($subnetBin, 0, $bytes)) {
                continue;
            }
            if ($bits === 0) {
                return true;
            }
            $maskByte = (~((1 << (8 - $bits)) - 1)) & 0xFF;
            if ((ord($ipBin[$bytes]) & $maskByte) === (ord($subnetBin[$bytes]) & $maskByte)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Отправляет общие заголовки страницы блокировки: 403, no-cache, X-Robots-Tag,
     * а также Retry-After, если известен timestamp окончания блокировки.
     */
    private static function sendBlockHeaders(?int $expireTime): void
    {
        header('HTTP/1.1 403 Forbidden');
        header('Content-Type: text/html; charset=utf-8');
        header('Cache-Control: no-store, private');
        header('Pragma: no-cache');
        header('X-Robots-Tag: noindex, nofollow');
        if ($expireTime !== null) {
            header('Retry-After: ' . max(1, $expireTime - time()));
        }
    }

    /**
     * Рендерит страницу 403 без каптчи.
     * Если $expireTime === null — бан перманентный, иначе показывается дата разблокировки.
     */
    private static function renderBlockedPage(?int $expireTime): void
    {
        self::sendBlockHeaders($expireTime);

        if ($expireTime === null) {
            $title = 'Доступ запрещён';
            $body = 'Ваш IP-адрес заблокирован. Для разблокировки свяжитесь с администратором сайта.';
        } else {
            $title = 'Доступ временно ограничен';
            $until = date('d.m.Y H:i', $expireTime);
            $body = 'Ваш IP-адрес временно заблокирован. Повторите попытку после ' . $until . '.';
        }

        $title = htmlspecialchars($title, ENT_QUOTES, 'UTF-8');
        $body = htmlspecialchars($body, ENT_QUOTES, 'UTF-8');

        echo <<<HTML
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{$title}</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #f5f5f5;
            color: #333;
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
            margin: 0;
            text-align: center;
        }
        .container {
            background: #fff;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            max-width: 450px;
            width: 100%;
        }
        h1 { font-size: 24px; margin-bottom: 20px; color: #d9534f; }
        p { font-size: 15px; margin-bottom: 0; line-height: 1.5; color: #555; }
    </style>
</head>
<body>
    <div class="container">
        <h1>{$title}</h1>
        <p>{$body}</p>
    </div>
</body>
</html>
HTML;
    }

    /**
     * Рендерит легковесную HTML-страницу с reCAPTCHA.
     */
    private static function renderCaptchaPage(?string $error, ?int $expireTime): void
    {
        self::sendBlockHeaders($expireTime);

        $siteKey = htmlspecialchars((string) self::$recaptchaSiteKey, ENT_QUOTES, 'UTF-8');
        $errorMessage = $error
            ? '<div class="error">' . htmlspecialchars($error, ENT_QUOTES, 'UTF-8') . '</div>'
            : '';
        $requestUri = htmlspecialchars($_SERVER['REQUEST_URI'] ?? '/', ENT_QUOTES, 'UTF-8');

        echo <<<HTML
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Доступ ограничен</title>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #f5f5f5;
            color: #333;
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
            margin: 0;
            text-align: center;
        }
        .container {
            background: #fff;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            max-width: 450px;
            width: 100%;
        }
        h1 { font-size: 24px; margin-bottom: 20px; color: #d9534f; }
        p { font-size: 15px; margin-bottom: 25px; line-height: 1.5; color: #555; }
        .error { color: #d9534f; margin-bottom: 15px; font-weight: bold; }
        .g-recaptcha { display: flex; justify-content: center; margin-bottom: 20px; }
        button {
            background: #0275d8;
            color: white;
            border: none;
            padding: 12px 25px;
            font-size: 16px;
            border-radius: 6px;
            cursor: pointer;
            width: 100%;
            transition: background 0.3s;
        }
        button:hover { background: #025aa5; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Подозрительная активность</h1>
        <p>Мы обнаружили подозрительные запросы с вашего IP-адреса. Пожалуйста, подтвердите, что вы человек, чтобы продолжить использование сайта.</p>
        {$errorMessage}
        <form method="POST" action="{$requestUri}">
            <div class="g-recaptcha" data-sitekey="{$siteKey}"></div>
            <button type="submit">Подтвердить и продолжить</button>
        </form>
    </div>
</body>
</html>
HTML;
    }

    /**
     * Безопасное завершение с минимальным раскрытием информации.
     */
    private static function terminate(string $message): never
    {
        if (PHP_SAPI !== 'cli') {
            header('HTTP/1.1 500 Internal Server Error');
        }
        exit($message);
    }
}
