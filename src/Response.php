<?php

declare(strict_types=1);

namespace Mitisk\Waf;

/**
 * Ответ WAF вместо приложения: страница блокировки, каптча, 404 или редирект.
 */
final class Response
{
    /**
     * @param array<string, string> $headers
     */
    public function __construct(
        public readonly int $status,
        public readonly array $headers,
        public readonly string $body,
    ) {
    }

    public function send(): void
    {
        if (!headers_sent()) {
            http_response_code($this->status);
            foreach ($this->headers as $name => $value) {
                header($name . ': ' . $value);
            }
        }
        echo $this->body;
    }

    /** Страница 403 без каптчи; $until = null — блокировка бессрочная. */
    public static function blocked(?int $until, int $now): self
    {
        if ($until === null) {
            $title = 'Доступ запрещён';
            $text = 'Ваш IP-адрес заблокирован. Для разблокировки свяжитесь с администратором сайта.';
        } else {
            $title = 'Доступ временно ограничен';
            $text = 'Ваш IP-адрес временно заблокирован. Повторите попытку после ' . date('d.m.Y H:i', $until) . '.';
        }

        return new self(403, self::blockHeaders($until, $now), self::page($title, '<p>' . self::e($text) . '</p>'));
    }

    /** Страница 403 с каптчей. */
    public static function captcha(string $siteKey, string $uri, ?string $error, ?int $until, int $now): self
    {
        $content = '<p>Мы обнаружили подозрительные запросы с вашего IP-адреса. Пожалуйста, подтвердите, '
            . 'что вы человек, чтобы продолжить использование сайта.</p>'
            . ($error !== null ? '<div class="error">' . self::e($error) . '</div>' : '')
            . '<form method="POST" action="' . self::e($uri) . '">'
            . '<div class="g-recaptcha" data-sitekey="' . self::e($siteKey) . '"></div>'
            . '<button type="submit">Подтвердить и продолжить</button>'
            . '</form>';

        return new self(
            403,
            self::blockHeaders($until, $now),
            self::page('Подозрительная активность', $content, '<script src="https://www.google.com/recaptcha/api.js" async defer></script>')
        );
    }

    /** 404 без блокировки: сомнительный адрес запросил тот, кого блокировать нельзя. */
    public static function notFound(): self
    {
        return new self(
            404,
            ['Content-Type' => 'text/html; charset=utf-8', 'Cache-Control' => 'no-store, private', 'X-Robots-Tag' => 'noindex, nofollow'],
            self::page('Страница не найдена', '<p>Такой страницы нет.</p>')
        );
    }

    public static function redirect(string $location): self
    {
        return new self(302, ['Location' => $location, 'Cache-Control' => 'no-store, private'], '');
    }

    /**
     * @return array<string, string>
     */
    private static function blockHeaders(?int $until, int $now): array
    {
        $headers = [
            'Content-Type' => 'text/html; charset=utf-8',
            'Cache-Control' => 'no-store, private',
            'Pragma' => 'no-cache',
            'X-Robots-Tag' => 'noindex, nofollow',
        ];
        if ($until !== null) {
            $headers['Retry-After'] = (string) max(1, $until - $now);
        }

        return $headers;
    }

    private static function page(string $title, string $content, string $head = ''): string
    {
        $title = self::e($title);

        return <<<HTML
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{$title}</title>
    {$head}
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #f5f5f5; color: #333;
            display: flex; align-items: center; justify-content: center;
            min-height: 100vh; margin: 0; text-align: center;
        }
        .container {
            background: #fff; padding: 40px; border-radius: 12px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1); max-width: 450px; width: 100%; box-sizing: border-box;
        }
        h1 { font-size: 24px; margin: 0 0 20px; color: #d9534f; }
        p { font-size: 15px; margin: 0 0 25px; line-height: 1.5; color: #555; }
        p:last-child { margin-bottom: 0; }
        .error { color: #d9534f; margin-bottom: 15px; font-weight: bold; }
        .g-recaptcha { display: flex; justify-content: center; margin-bottom: 20px; }
        button {
            background: #0275d8; color: #fff; border: none; padding: 12px 25px; font-size: 16px;
            border-radius: 6px; cursor: pointer; width: 100%; transition: background 0.3s;
        }
        button:hover { background: #025aa5; }
    </style>
</head>
<body>
    <div class="container">
        <h1>{$title}</h1>
        {$content}
    </div>
</body>
</html>
HTML;
    }

    private static function e(string $text): string
    {
        return htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}
