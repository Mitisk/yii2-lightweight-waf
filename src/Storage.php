<?php

declare(strict_types=1);

namespace Mitisk\Waf;

/**
 * Файловое хранилище WAF в папке <runtime>/waf_blocks: блокировки, счётчики каптчи, журнал,
 * настройки панели управления.
 *
 * Файлы с данными — «JSON под замком»: первая строка — PHP-код, который отвечает 404 и завершает
 * работу, дальше JSON. Если папка runtime окажется доступна по HTTP (корень сайта — папка проекта),
 * запрос файла не отдаст ни адресов посетителей, ни ключей каптчи. Сами файлы никогда не
 * подключаются через include — только читаются.
 */
final class Storage
{
    public const GUARD = "<?php http_response_code(404); exit; ?>\n";

    private const BLOCK_PREFIX = 'block_';
    private const CAPTCHA_PREFIX = 'captcha_';
    private const SETTINGS_FILE = 'settings.php';
    private const EVENTS_FILE = 'events.php';
    private const EVENTS_OLD_FILE = 'events.1.php';
    private const CLEANUP_STAMP = 'cleanup.stamp';
    private const LEGACY_BANS_FILE = 'banned_ips.json';

    /** Журнал больше этого размера уходит в events.1.php (хранится одно прошлое поколение). */
    public const EVENTS_MAX_BYTES = 1048576;

    /** Не чаще раза в час. */
    public const CLEANUP_INTERVAL = 3600;

    /** Счётчики каптчи и файлы блокировок старого формата живут 2 дня. */
    private const STALE_AGE = 172800;

    /** «Навсегда» для mtime файла бессрочной блокировки: 10 лет. */
    private const FOREVER = 315360000;

    private const JSON_FLAGS = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE | JSON_HEX_TAG;

    public function __construct(public readonly string $dir)
    {
    }

    // ─── Блокировки ──────────────────────────────────────────────

    /**
     * Действующая блокировка по ключу (IP или сеть /64). Истёкшая удаляется.
     *
     * @return array<string, mixed>|null
     */
    public function findBlock(string $key, int $now): ?array
    {
        $file = $this->blockFile($key);
        if (!is_file($file)) {
            return null;
        }
        $block = $this->readGuarded($file);
        if ($block === null) {
            return null;
        }
        $until = (int) ($block['until'] ?? 0);
        if ($until !== 0 && $until <= $now) {
            @unlink($file);
            return null;
        }

        return $block;
    }

    /**
     * @param array{key: string, ip: string, at: int, until: int, uri?: string, pattern?: string, ua?: string, reason?: string} $block
     *        until = 0 — бессрочно
     */
    public function saveBlock(array $block): bool
    {
        if (!$this->ensureDir()) {
            return false;
        }
        $file = $this->blockFile($block['key']);
        if (!$this->writeGuarded($file, $block)) {
            return false;
        }
        // mtime = срок: уборка находит истёкшие файлы, не читая каждый
        @touch($file, $block['until'] !== 0 ? $block['until'] : $block['at'] + self::FOREVER);

        return true;
    }

    public function deleteBlock(string $key): bool
    {
        $file = $this->blockFile($key);

        return is_file($file) && @unlink($file);
    }

    /**
     * Все действующие блокировки, новые первыми.
     *
     * @return array<int, array<string, mixed>>
     */
    public function allBlocks(int $now, int $limit = 5000): array
    {
        $blocks = [];
        foreach ($this->files(self::BLOCK_PREFIX, '.php') as $file) {
            $block = $this->readGuarded($file);
            if ($block === null || empty($block['key'])) {
                continue;
            }
            $until = (int) ($block['until'] ?? 0);
            if ($until !== 0 && $until <= $now) {
                continue;
            }
            $blocks[] = $block;
            if (count($blocks) >= $limit) {
                break;
            }
        }
        usort($blocks, static fn (array $a, array $b): int => ($b['at'] ?? 0) <=> ($a['at'] ?? 0));

        return $blocks;
    }

    // ─── Каптча ──────────────────────────────────────────────────

    /**
     * @return array{0: int, 1: int} [число неудач, начало окна]
     */
    public function captchaAttempts(string $key): array
    {
        $raw = (string) @file_get_contents($this->captchaFile($key));
        if (!str_contains($raw, '|')) {
            return [0, 0];
        }
        [$count, $start] = explode('|', $raw, 2);

        return [(int) $count, (int) $start];
    }

    public function saveCaptchaAttempts(string $key, int $count, int $start): void
    {
        if ($this->ensureDir()) {
            @file_put_contents($this->captchaFile($key), $count . '|' . $start, LOCK_EX);
        }
    }

    public function clearCaptchaAttempts(string $key): void
    {
        @unlink($this->captchaFile($key));
    }

    // ─── Журнал ──────────────────────────────────────────────────

    /**
     * @param array<string, mixed> $event
     */
    public function appendEvent(array $event): void
    {
        if (!$this->ensureDir()) {
            return;
        }
        $file = $this->path(self::EVENTS_FILE);
        if (is_file($file) && (int) @filesize($file) > self::EVENTS_MAX_BYTES) {
            @rename($file, $this->path(self::EVENTS_OLD_FILE));
            clearstatcache(true, $file);
        }
        $line = json_encode($event, self::JSON_FLAGS);
        if ($line === false) {
            return;
        }
        $prefix = is_file($file) ? '' : self::GUARD;
        @file_put_contents($file, $prefix . $line . "\n", FILE_APPEND | LOCK_EX);
    }

    /**
     * Последние события, новые первыми.
     *
     * @return array<int, array<string, mixed>>
     */
    public function events(int $limit = 200): array
    {
        $events = [];
        foreach ([self::EVENTS_FILE, self::EVENTS_OLD_FILE] as $name) {
            $raw = @file_get_contents($this->path($name));
            if (!is_string($raw) || $raw === '') {
                continue;
            }
            $lines = explode("\n", $raw);
            for ($i = count($lines) - 1; $i >= 1 && count($events) < $limit; $i--) {
                if ($lines[$i] === '') {
                    continue;
                }
                $event = json_decode($lines[$i], true);
                if (is_array($event)) {
                    $events[] = $event;
                }
            }
            if (count($events) >= $limit) {
                break;
            }
        }

        return $events;
    }

    // ─── Настройки панели управления ─────────────────────────────

    /**
     * @return array<string, mixed>|null null — настройки не сохранялись
     */
    public function readSettings(): ?array
    {
        $file = $this->path(self::SETTINGS_FILE);

        return is_file($file) ? $this->readGuarded($file) : null;
    }

    /**
     * @param array<string, mixed> $settings
     */
    public function writeSettings(array $settings): bool
    {
        if (!$this->ensureDir()) {
            return false;
        }
        $file = $this->path(self::SETTINGS_FILE);
        $tmp = $file . '.' . bin2hex(random_bytes(4)) . '.tmp';
        if (!$this->writeGuarded($tmp, $settings)) {
            @unlink($tmp);
            return false;
        }
        if (!@rename($tmp, $file)) {
            @unlink($tmp);
            return false;
        }
        clearstatcache(true, $file);

        return true;
    }

    public function deleteSettings(): void
    {
        @unlink($this->path(self::SETTINGS_FILE));
    }

    // ─── Обслуживание ────────────────────────────────────────────

    /**
     * Уборка не чаще раза в час: истёкшие блокировки, старые счётчики каптчи, файлы прежнего
     * формата. true — уборка выполнена в этот вызов.
     */
    public function cleanup(int $now): bool
    {
        if (!is_dir($this->dir)) {
            return false;
        }
        $stamp = $this->path(self::CLEANUP_STAMP);
        if (is_file($stamp) && (int) @filemtime($stamp) > $now - self::CLEANUP_INTERVAL) {
            return false;
        }
        @touch($stamp, $now);
        $this->protectDir();

        foreach ($this->files(self::BLOCK_PREFIX, '.php') as $file) {
            // mtime — срок блокировки; содержимое — истина (mtime мог сбросить бэкап)
            if ((int) @filemtime($file) > $now) {
                continue;
            }
            $block = $this->readGuarded($file);
            $until = (int) ($block['until'] ?? 0);
            if ($block === null || ($until !== 0 && $until <= $now)) {
                @unlink($file);
            } else {
                @touch($file, $until !== 0 ? $until : $now + self::FOREVER);
            }
        }

        $stale = $now - self::STALE_AGE;
        foreach (array_merge($this->files(self::CAPTCHA_PREFIX, '.txt'), $this->files(self::BLOCK_PREFIX, '.txt')) as $file) {
            if ((int) @filemtime($file) < $stale) {
                @unlink($file);
            }
        }

        return true;
    }

    /**
     * Перенос бессрочных блокировок из banned_ips.json (формат до версии 2.1) в отдельные файлы.
     *
     * @return int сколько адресов перенесено
     */
    public function importLegacyBans(int $now): int
    {
        $file = $this->path(self::LEGACY_BANS_FILE);
        if (!is_file($file)) {
            return 0;
        }
        $ips = json_decode((string) @file_get_contents($file), true);
        $count = 0;
        foreach (is_array($ips) ? $ips : [] as $ip) {
            if (!is_string($ip) || IpTools::normalize($ip) === null) {
                continue;
            }
            $key = IpTools::banKey($ip);
            if (!is_file($this->blockFile($key))) {
                $this->saveBlock(['key' => $key, 'ip' => $ip, 'at' => $now, 'until' => 0, 'reason' => 'legacy']);
                $count++;
            }
        }
        @rename($file, $this->path('banned_ips.imported.json'));

        return $count;
    }

    public function hasLegacyBans(): bool
    {
        return is_file($this->path(self::LEGACY_BANS_FILE));
    }

    // ─── Внутреннее ──────────────────────────────────────────────

    private function blockFile(string $key): string
    {
        return $this->path(self::BLOCK_PREFIX . md5($key) . '.php');
    }

    private function captchaFile(string $key): string
    {
        return $this->path(self::CAPTCHA_PREFIX . md5($key) . '.txt');
    }

    private function path(string $name): string
    {
        return $this->dir . DIRECTORY_SEPARATOR . $name;
    }

    /**
     * @return string[] полные пути файлов папки с данным началом и концом имени
     */
    private function files(string $prefix, string $suffix): array
    {
        $names = is_dir($this->dir) ? @scandir($this->dir) : false;
        $files = [];
        foreach ($names ?: [] as $name) {
            if (str_starts_with($name, $prefix) && str_ends_with($name, $suffix)) {
                $files[] = $this->path($name);
            }
        }

        return $files;
    }

    private function ensureDir(): bool
    {
        if (is_dir($this->dir)) {
            return true;
        }
        if (!@mkdir($this->dir, 0755, true) && !is_dir($this->dir)) {
            return false;
        }
        $this->protectDir();

        return true;
    }

    /** Закрывает папку от прямых HTTP-запросов на Apache (на nginx защищает замок в самих файлах). */
    private function protectDir(): void
    {
        $htaccess = $this->path('.htaccess');
        if (!is_file($htaccess)) {
            @file_put_contents(
                $htaccess,
                "<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n"
                . "<IfModule !mod_authz_core.c>\n    Deny from all\n</IfModule>\n"
            );
        }
    }

    /**
     * @return array<string, mixed>|null
     */
    private function readGuarded(string $file): ?array
    {
        $raw = @file_get_contents($file);
        if (!is_string($raw)) {
            return null;
        }
        $pos = strpos($raw, "\n");
        if ($pos === false) {
            return null;
        }
        $data = json_decode(substr($raw, $pos + 1), true);

        return is_array($data) ? $data : null;
    }

    /**
     * @param array<string, mixed> $data
     */
    private function writeGuarded(string $file, array $data): bool
    {
        $json = json_encode($data, self::JSON_FLAGS);

        return $json !== false && @file_put_contents($file, self::GUARD . $json, LOCK_EX) !== false;
    }
}
