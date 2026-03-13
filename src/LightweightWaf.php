<?php

namespace Mitisk\Waf;

/**
 * Lightweight WAF (Web Application Firewall)
 * Предназначен для защиты от автоматических сканеров уязвимостей (dirsearch, wp-scanners и др.)
 * Работает на раннем этапе загрузки до инициализации тяжелого ядра Yii2.
 */
class LightweightWaf
{
    /**
     * @var array Словарь плохих паттернов URI по умолчанию
     */
    private static $badPatterns = [
        '/admin.php',
        '/wp-login.php',
        '/wp-admin',
        '/.env',
        '/xmlrpc.php',
        '/bitrix/admin',
        '/.git',
        '/config.json',
        '/phpunit.xml'
    ];

    /**
     * @var string Путь к директории хранения заблокированных IP
     */
    private static $storageDir;

    /**
     * @var string Секретный ключ Google reCAPTCHA v2
     */
    private static $recaptchaSecret;

    /**
     * @var string Публичный ключ (Site Key) Google reCAPTCHA v2
     */
    private static $recaptchaSiteKey;

    /**
     * @var int Время блокировки в секундах
     */
    private static $blockDuration = 86400;

    /**
     * Точка входа для WAF. Вызывается в web/index.php.
     * 
     * @param array $config Конфигурационные параметры:
     * - runtimePath (string, required): Путь до папки runtime
     * - recaptchaSiteKey (string, required): Публичный ключ каптчи
     * - recaptchaSecret (string, required): Приватный ключ каптчи
     * - badPatterns (array, optional): Массив уязвимых путей для блокировки
     * - blockDuration (int, optional): Время блокировки в секундах (по умолчанию 86400)
     */
    public static function run(array $config)
    {
        if (empty($config['runtimePath'])) {
            die("LightweightWaf Error: 'runtimePath' parameter is required.");
        }
        if (empty($config['recaptchaSiteKey']) || empty($config['recaptchaSecret'])) {
            die("LightweightWaf Error: reCAPTCHA keys ('recaptchaSiteKey', 'recaptchaSecret') are required.");
        }

        self::$storageDir = rtrim($config['runtimePath'], '/\\') . DIRECTORY_SEPARATOR . 'waf_blocks';
        self::$recaptchaSiteKey = $config['recaptchaSiteKey'];
        self::$recaptchaSecret = $config['recaptchaSecret'];
        
        if (!empty($config['badPatterns']) && is_array($config['badPatterns'])) {
            self::$badPatterns = $config['badPatterns'];
        }
        if (isset($config['blockDuration'])) {
            self::$blockDuration = (int)$config['blockDuration'];
        }

        $ip = self::getClientIp();
        $uri = $_SERVER['REQUEST_URI'] ?? '/';
        $blockFile = self::$storageDir . DIRECTORY_SEPARATOR . 'block_' . md5($ip) . '.txt';

        // 1. Проверяем, находится ли IP в черном списке
        if (file_exists($blockFile)) {
            $expireTime = (int)@file_get_contents($blockFile);
            if (time() < $expireTime) {
                // IP всё ещё заблокирован, обрабатываем запрос
                self::handleBlockedRequest($ip, $blockFile);
                exit; // Прерываем выполнение
            } else {
                // Время блокировки истекло, удаляем файл
                @unlink($blockFile);
            }
        }

        // 2. Проверяем URI на совпадение с плохими паттернами
        $uriLower = strtolower($uri);
        foreach (self::$badPatterns as $pattern) {
            if (strpos($uriLower, strtolower($pattern)) !== false) {
                // Обнаружена угроза! Блокируем IP
                self::blockIp($blockFile);
                self::handleBlockedRequest($ip, $blockFile);
                exit; // Прерываем выполнение
            }
        }
    }

    /**
     * Блокирует IP-адрес путем создания файла с timestamp окончания блокировки.
     */
    private static function blockIp($blockFile)
    {
        if (!is_dir(self::$storageDir)) {
            // Создаем директорию с правами 0775, если её нет
            @mkdir(self::$storageDir, 0775, true);
        }
        @file_put_contents($blockFile, time() + self::$blockDuration, LOCK_EX);
    }

    /**
     * Обрабатывает заблокированный запрос: проверяет POST каптчи или показывает страницу-заглушку.
     */
    private static function handleBlockedRequest($ip, $blockFile)
    {
        $error = null;

        // Если прилетел POST-запрос с токеном каптчи
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['g-recaptcha-response'])) {
            if (self::verifyCaptcha($_POST['g-recaptcha-response'], $ip)) {
                // Каптча успешно пройдена: удаляем IP из блэклиста
                @unlink($blockFile);
                // Редирект на главную страницу, чтобы сбросить POST-запрос и плохой URI
                header("Location: /", true, 302);
                exit;
            } else {
                $error = "Каптча не пройдена или устарела. Попробуйте еще раз.";
            }
        }

        // Если мы здесь, значит нужно показать страницу с каптчой
        self::renderCaptchaPage($error);
    }

    /**
     * Валидация токена reCAPTCHA через API Google.
     */
    private static function verifyCaptcha($response, $ip)
    {
        $url = 'https://www.google.com/recaptcha/api/siteverify';
        $data = [
            'secret' => self::$recaptchaSecret,
            'response' => $response,
            'remoteip' => $ip
        ];

        $options = [
            'http' => [
                'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
                'method'  => 'POST',
                'content' => http_build_query($data),
                'timeout' => 5 // Таймаут 5 секунд, чтобы не зависнуть
            ]
        ];

        $context  = stream_context_create($options);
        $result = @file_get_contents($url, false, $context);
        
        if ($result === false) {
            return false;
        }

        $json = json_decode($result, true);
        return !empty($json['success']);
    }

    /**
     * Получает реальный IP-адрес клиента, учитывая прокси (Cloudflare, Nginx и т.д.).
     */
    private static function getClientIp()
    {
        $headersInfo = [
            'HTTP_CLIENT_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_X_CLUSTER_CLIENT_IP',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'REMOTE_ADDR'
        ];

        foreach ($headersInfo as $key) {
            if (array_key_exists($key, $_SERVER) === true) {
                foreach (explode(',', $_SERVER[$key]) as $ip) {
                    $ip = trim($ip); 
                    // Проверка на валидность IP-адреса
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
                        return $ip;
                    }
                }
            }
        }
        return $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    }

    /**
     * Рендерит легковесную HTML-страницу с reCAPTCHA.
     */
    private static function renderCaptchaPage($error = null)
    {
        // 403 статус-код сообщает ботам (и SEO), что сюда лезть не нужно
        header('HTTP/1.1 403 Forbidden');
        header('Content-Type: text/html; charset=utf-8');

        $siteKey = htmlspecialchars(self::$recaptchaSiteKey, ENT_QUOTES, 'UTF-8');
        $errorMessage = $error ? "<div class='error'>" . htmlspecialchars($error, ENT_QUOTES, 'UTF-8') . "</div>" : "";
        $requestUri = htmlspecialchars($_SERVER['REQUEST_URI'], ENT_QUOTES, 'UTF-8');

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
}
