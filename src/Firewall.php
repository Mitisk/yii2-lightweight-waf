<?php

declare(strict_types=1);

namespace Mitisk\Waf;

/**
 * Решение по запросу: пропустить в приложение (null) или ответить самому.
 *
 * Порядок: выключен → белый список → действующая блокировка → шаблоны пути.
 * При срабатывании шаблона: режим наблюдения (только журнал), запрос со стороннего сайта
 * и подтверждённый поисковый робот (404 без блокировки), иначе — блокировка.
 */
final class Firewall
{
    private const URI_LOG_LENGTH = 300;
    private const UA_LOG_LENGTH = 200;

    private Storage $storage;

    private BotVerifier $bots;

    /** @var callable(): int */
    private $clock;

    /** @var callable(string, string): bool */
    private $captchaVerifier;

    /** @var callable(): bool */
    private $maintenanceDue;

    /**
     * @param (callable(): int)|null $clock текущее время
     * @param (callable(string, string): bool)|null $captchaVerifier (токен, ip) → каптча пройдена
     * @param (callable(): bool)|null $maintenanceDue пора ли проверить уборку (по умолчанию — 1 запрос из 50)
     */
    public function __construct(
        private readonly Config $config,
        ?Storage $storage = null,
        ?callable $clock = null,
        ?callable $captchaVerifier = null,
        ?BotVerifier $bots = null,
        ?callable $maintenanceDue = null,
    ) {
        $this->storage = $storage ?? new Storage($config->storageDir);
        $this->clock = $clock ?? static fn (): int => time();
        $this->bots = $bots ?? new BotVerifier();
        $this->maintenanceDue = $maintenanceDue ?? static fn (): bool => mt_rand(1, 50) === 1;
        $secret = (string) $config->recaptchaSecret;
        $this->captchaVerifier = $captchaVerifier
            ?? static fn (string $token, string $ip): bool => Recaptcha::verify($secret, $token, $ip);
    }

    /**
     * @param array<string, mixed> $server $_SERVER
     * @param array<string, mixed> $post $_POST
     */
    public function handle(array $server, array $post = []): ?Response
    {
        $config = $this->config;
        if (!$config->enabled) {
            return null;
        }

        $ip = IpTools::clientIp($server, $config->trustedHeaders, $config->trustedProxies);
        if ($config->allowIps !== [] && IpTools::inList($ip, $config->allowIps)) {
            return null;
        }

        $now = ($this->clock)();
        $this->maintenance($now);

        $key = IpTools::banKey($ip);
        $uri = (string) ($server['REQUEST_URI'] ?? '/');

        if (!$config->observeOnly) {
            $block = $this->storage->findBlock($key, $now);
            if ($block !== null) {
                return $this->blocked($block, $ip, $key, $uri, $server, $post, $now);
            }
        }

        $pattern = $this->matchPattern($uri);
        if ($pattern === null) {
            return null;
        }

        $userAgent = (string) ($server['HTTP_USER_AGENT'] ?? '');
        $event = ['ip' => $ip, 'uri' => $uri, 'pattern' => $pattern, 'ua' => $userAgent];

        if ($config->observeOnly) {
            $this->log($now, 'observe', $event);
            return null;
        }
        if ($config->skipCrossSite && strtolower((string) ($server['HTTP_SEC_FETCH_SITE'] ?? '')) === 'cross-site') {
            $this->log($now, 'skip', $event + ['note' => 'cross-site']);
            return Response::notFound();
        }
        if ($config->verifyBots && $this->bots->isVerified($ip, $userAgent)) {
            $this->log($now, 'skip', $event + ['note' => 'bot']);
            return Response::notFound();
        }

        $block = [
            'key' => $key,
            'ip' => $ip,
            'at' => $now,
            'until' => $config->permanentBlock ? 0 : $now + $config->blockDuration,
            'uri' => self::cut($uri, self::URI_LOG_LENGTH),
            'pattern' => $pattern,
            'ua' => self::cut($userAgent, self::UA_LOG_LENGTH),
            'reason' => 'pattern',
        ];
        $this->storage->saveBlock($block);
        $this->log($now, 'ban', $event);

        return $this->blocked($block, $ip, $key, $uri, $server, $post, $now);
    }

    /**
     * Шаблон, под который подходит адрес, или null. Сравнивается путь (без параметров запроса,
     * если не включён matchQuery), раскодированный из %XX, без учёта регистра.
     */
    public function matchPattern(string $uri): ?string
    {
        if (!$this->config->matchQuery) {
            $uri = explode('?', $uri, 2)[0];
        }
        // Два прохода: /%252eenv → /%2eenv → /.env
        $subject = strtolower(rawurldecode(rawurldecode($uri)));

        foreach ($this->config->patterns() as $pattern) {
            if (str_contains($subject, $pattern)) {
                return $pattern;
            }
        }

        return null;
    }

    /**
     * Ответ заблокированному: каптча, если настроена и попытки не исчерпаны, иначе страница 403.
     *
     * @param array<string, mixed> $block
     * @param array<string, mixed> $server
     * @param array<string, mixed> $post
     */
    private function blocked(array $block, string $ip, string $key, string $uri, array $server, array $post, int $now): Response
    {
        $config = $this->config;
        $until = (int) ($block['until'] ?? 0) !== 0 ? (int) $block['until'] : null;

        if (!$config->captchaConfigured() || $this->captchaAttemptsExceeded($key, $now)) {
            return Response::blocked($until, $now);
        }

        $error = null;
        $token = $post['g-recaptcha-response'] ?? '';
        if (($server['REQUEST_METHOD'] ?? '') === 'POST' && is_string($token) && $token !== '') {
            if (($this->captchaVerifier)($token, $ip)) {
                $this->storage->clearCaptchaAttempts($key);
                $this->storage->deleteBlock($key);
                $this->log($now, 'captcha_ok', ['ip' => $ip]);

                return Response::redirect('/');
            }

            $remaining = $this->recordCaptchaFailure($key, $now);
            $this->log($now, 'captcha_fail', ['ip' => $ip]);
            if ($remaining <= 0) {
                return Response::blocked($until, $now);
            }
            $error = 'Каптча не пройдена или устарела. Осталось попыток: ' . $remaining . '.';
        }

        return Response::captcha((string) $config->recaptchaSiteKey, $uri, $error, $until, $now);
    }

    private function captchaAttemptsExceeded(string $key, int $now): bool
    {
        [$count, $start] = $this->storage->captchaAttempts($key);
        if ($count < $this->config->captchaMaxAttempts) {
            return false;
        }
        if ($now - $start >= $this->config->captchaWindow) {
            $this->storage->clearCaptchaAttempts($key);
            return false;
        }

        return true;
    }

    /** @return int сколько попыток осталось */
    private function recordCaptchaFailure(string $key, int $now): int
    {
        [$count, $start] = $this->storage->captchaAttempts($key);
        if ($start === 0 || $now - $start >= $this->config->captchaWindow) {
            $count = 0;
            $start = $now;
        }
        $count++;
        $this->storage->saveCaptchaAttempts($key, $count, $start);

        return max(0, $this->config->captchaMaxAttempts - $count);
    }

    private function maintenance(int $now): void
    {
        if ($this->config->permanentBlock && $this->storage->hasLegacyBans()) {
            $this->storage->importLegacyBans($now);
        }
        if (($this->maintenanceDue)()) {
            $this->storage->cleanup($now);
        }
    }

    /**
     * @param array<string, mixed> $data
     */
    private function log(int $now, string $action, array $data): void
    {
        if (!$this->config->logEvents) {
            return;
        }
        if (isset($data['uri'])) {
            $data['uri'] = self::cut((string) $data['uri'], self::URI_LOG_LENGTH);
        }
        if (isset($data['ua'])) {
            $data['ua'] = self::cut((string) $data['ua'], self::UA_LOG_LENGTH);
        }
        $this->storage->appendEvent(['time' => $now, 'action' => $action] + $data);
    }

    private static function cut(string $text, int $length): string
    {
        return strlen($text) > $length ? substr($text, 0, $length) : $text;
    }
}
