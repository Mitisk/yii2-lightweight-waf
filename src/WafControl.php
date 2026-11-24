<?php

declare(strict_types=1);

namespace Mitisk\Waf;

/**
 * Управление WAF из панели администратора: настройки, список блокировок, журнал, статистика.
 *
 * Не зависит от фреймворка. Настройки пишутся в файл settings.php папки хранилища; WAF читает его
 * на следующем запросе и накладывает поверх конфига из web/index.php (только ключи
 * {@see Config::ADMIN_KEYS}).
 *
 * ```php
 * $waf = WafControl::current(Yii::getAlias('@runtime'));   // папка та же, с которой WAF запущен в index.php
 * $waf->saveSettings(['observeOnly' => true, 'allowIps' => ['203.0.113.0/24']], ['/', '/admin/']);
 * $waf->blocks(); $waf->unblock('203.0.113.9'); $waf->events(100); $waf->stats(7);
 * ```
 */
final class WafControl
{
    /** Версия этого интерфейса: панель управления сверяет её перед работой. */
    public const API = 1;

    private const MAX_BLOCK_DURATION = 315360000;

    private Storage $storage;

    /** @var callable(): int */
    private $clock;

    /**
     * @param string $storageDir папка хранилища (<runtime>/waf_blocks)
     * @param (callable(): int)|null $clock текущее время (для тестов)
     */
    public function __construct(string $storageDir, ?callable $clock = null)
    {
        $this->storage = new Storage($storageDir);
        $this->clock = $clock ?? static fn (): int => time();
    }

    /**
     * Хранилище WAF, отработавшего в этом запросе. Если run() не вызывался (консоль, WAF не подключён
     * в index.php) — папка waf_blocks в $runtimePath; без неё — null.
     */
    public static function current(?string $runtimePath = null): ?self
    {
        $dir = LightweightWaf::storageDir();
        if ($dir === null && $runtimePath !== null && $runtimePath !== '') {
            $dir = rtrim($runtimePath, '/\\') . DIRECTORY_SEPARATOR . 'waf_blocks';
        }

        return $dir === null ? null : new self($dir);
    }

    public function storageDir(): string
    {
        return $this->storage->dir;
    }

    // ─── Настройки ───────────────────────────────────────────────

    /**
     * Сохранённые настройки панели управления; [] — не сохранялись (действует конфиг из кода).
     *
     * @return array<string, mixed>
     */
    public function settings(): array
    {
        return $this->storage->readSettings() ?? [];
    }

    /**
     * Проверяет и сохраняет настройки. Ключи вне {@see Config::ADMIN_KEYS} отбрасываются.
     *
     * @param array<string, mixed> $settings
     * @param string[] $safePaths пути, которые новые шаблоны не должны блокировать (главная, панель управления)
     * @return array<string, mixed> сохранённые (приведённые к типам) настройки
     * @throws SettingsException настройки неверны, ничего не сохранено
     * @throws \RuntimeException файл настроек не записался
     */
    public function saveSettings(array $settings, array $safePaths = ['/']): array
    {
        [$clean, $errors] = $this->validate($settings, $safePaths);
        if ($errors !== []) {
            throw new SettingsException($errors);
        }
        if (!$this->storage->writeSettings($clean)) {
            throw new \RuntimeException('Не удалось записать настройки WAF в ' . $this->storage->dir);
        }

        return $clean;
    }

    /** Убирает настройки панели управления: снова действует только конфиг из кода. */
    public function resetSettings(): void
    {
        $this->storage->deleteSettings();
    }

    /**
     * Какой шаблон сработал бы на адресе при сохранённых настройках, или null.
     *
     * @param array<string, mixed> $codeConfig конфиг из index.php (badPatterns, matchQuery…), если известен
     */
    public function check(string $uri, array $codeConfig = []): ?string
    {
        $config = Config::fromArray($codeConfig);
        $config->applyAdminSettings($this->settings());

        return (new Firewall($config, $this->storage))->matchPattern($uri);
    }

    // ─── Блокировки ──────────────────────────────────────────────

    /**
     * Действующие блокировки, новые первыми: key, ip, at, until (0 — бессрочно), uri, pattern, ua, reason.
     *
     * @return array<int, array<string, mixed>>
     */
    public function blocks(int $limit = 5000): array
    {
        return $this->storage->allBlocks(($this->clock)(), $limit);
    }

    /**
     * Блокирует адрес вручную.
     *
     * @param int|null $seconds срок; null — бессрочно
     * @return array<string, mixed> запись блокировки
     * @throws \InvalidArgumentException не IP-адрес
     * @throws \RuntimeException запись не сохранилась
     */
    public function block(string $ip, ?int $seconds, string $note = ''): array
    {
        $normalized = IpTools::normalize($ip);
        if ($normalized === null) {
            throw new \InvalidArgumentException('Не IP-адрес: ' . $ip);
        }
        $now = ($this->clock)();
        $block = [
            'key' => IpTools::banKey($normalized),
            'ip' => $normalized,
            'at' => $now,
            'until' => $seconds === null ? 0 : $now + max(Config::MIN_BLOCK_DURATION, $seconds),
            'reason' => 'manual',
            'note' => function_exists('mb_substr') ? mb_substr($note, 0, 200) : substr($note, 0, 200),
        ];
        if (!$this->storage->saveBlock($block)) {
            throw new \RuntimeException('Не удалось записать блокировку в ' . $this->storage->dir);
        }
        $this->storage->appendEvent(['time' => $now, 'action' => 'manual_ban', 'ip' => $normalized, 'note' => $block['note']]);

        return $block;
    }

    /**
     * Снимает блокировку по адресу или по ключу сети («2001:db8:1:2::/64»).
     * false — такой блокировки нет.
     */
    public function unblock(string $ipOrKey): bool
    {
        $key = str_contains($ipOrKey, '/') ? $ipOrKey : IpTools::banKey($ipOrKey);
        $this->storage->clearCaptchaAttempts($key);
        if (!$this->storage->deleteBlock($key)) {
            return false;
        }
        $this->storage->appendEvent(['time' => ($this->clock)(), 'action' => 'unban', 'ip' => $ipOrKey]);

        return true;
    }

    // ─── Журнал и статистика ─────────────────────────────────────

    /**
     * Последние события, новые первыми: time, action (ban | observe | skip | captcha_ok |
     * captcha_fail | manual_ban | unban), ip, uri, pattern, ua, note.
     *
     * @return array<int, array<string, mixed>>
     */
    public function events(int $limit = 200): array
    {
        return $this->storage->events($limit);
    }

    /**
     * Блокировки по шаблонам за последние дни (по журналу) и число действующих блокировок.
     *
     * @return array{bans: int, active: int, byDay: array<string, int>} byDay — «ГГГГ-ММ-ДД» → число, от старых к новым
     */
    public function stats(int $days = 7): array
    {
        $now = ($this->clock)();
        $byDay = [];
        for ($i = $days - 1; $i >= 0; $i--) {
            $byDay[date('Y-m-d', $now - $i * 86400)] = 0;
        }
        foreach ($this->storage->events(PHP_INT_MAX) as $event) {
            if (($event['action'] ?? '') !== 'ban') {
                continue;
            }
            $day = date('Y-m-d', (int) ($event['time'] ?? 0));
            if (isset($byDay[$day])) {
                $byDay[$day]++;
            }
        }

        return ['bans' => array_sum($byDay), 'active' => count($this->blocks()), 'byDay' => $byDay];
    }

    // ─── Проверка настроек ───────────────────────────────────────

    /**
     * @param array<string, mixed> $settings
     * @param string[] $safePaths
     * @return array{0: array<string, mixed>, 1: array<string, string>}
     */
    private function validate(array $settings, array $safePaths): array
    {
        $clean = [];
        $errors = [];

        foreach (['enabled', 'observeOnly', 'permanentBlock', 'skipCrossSite', 'verifyBots'] as $key) {
            if (array_key_exists($key, $settings)) {
                $clean[$key] = filter_var($settings[$key], FILTER_VALIDATE_BOOLEAN);
            }
        }

        $ranges = [
            'blockDuration' => [Config::MIN_BLOCK_DURATION, self::MAX_BLOCK_DURATION, 'Срок блокировки — от 60 секунд до 10 лет.'],
            'captchaMaxAttempts' => [1, 100, 'Число попыток каптчи — от 1 до 100.'],
            'captchaWindow' => [60, 86400, 'Окно попыток каптчи — от 60 секунд до суток.'],
        ];
        foreach ($ranges as $key => [$min, $max, $message]) {
            if (!array_key_exists($key, $settings)) {
                continue;
            }
            $value = filter_var($settings[$key], FILTER_VALIDATE_INT);
            if ($value === false || $value < $min || $value > $max) {
                $errors[$key] = $message;
            } else {
                $clean[$key] = $value;
            }
        }

        if (array_key_exists('allowIps', $settings)) {
            $clean['allowIps'] = [];
            foreach (self::lines($settings['allowIps']) as $cidr) {
                if (!IpTools::isValidCidr($cidr)) {
                    $errors['allowIps'] = 'Не адрес и не сеть: «' . $cidr . '». Примеры: 203.0.113.5, 10.0.0.0/8, 2001:db8::/32.';
                    break;
                }
                $clean['allowIps'][] = $cidr;
            }
        }

        if (array_key_exists('disabledPatterns', $settings)) {
            $clean['disabledPatterns'] = array_map('strtolower', self::lines($settings['disabledPatterns']));
        }

        if (array_key_exists('extraPatterns', $settings)) {
            $clean['extraPatterns'] = [];
            foreach (self::lines($settings['extraPatterns']) as $pattern) {
                $pattern = strtolower($pattern);
                if (strlen($pattern) < Config::MIN_PATTERN_LENGTH) {
                    $errors['extraPatterns'] = 'Шаблон «' . $pattern . '» слишком короткий: нужно не меньше '
                        . Config::MIN_PATTERN_LENGTH . ' символов, иначе он заблокирует всех.';
                    break;
                }
                foreach ($safePaths as $path) {
                    if (str_contains(strtolower($path), $pattern)) {
                        $errors['extraPatterns'] = 'Шаблон «' . $pattern . '» заблокировал бы адрес ' . $path . '.';
                        break 2;
                    }
                }
                $clean['extraPatterns'][] = $pattern;
            }
            $clean['extraPatterns'] = array_values(array_unique($clean['extraPatterns']));
        }

        foreach (['recaptchaSiteKey', 'recaptchaSecret'] as $key) {
            if (array_key_exists($key, $settings)) {
                $clean[$key] = trim((string) $settings[$key]);
            }
        }
        $siteKey = $clean['recaptchaSiteKey'] ?? null;
        $secret = $clean['recaptchaSecret'] ?? null;
        if (($siteKey !== null || $secret !== null) && (($siteKey ?? '') === '') !== (($secret ?? '') === '')) {
            $missing = ($siteKey ?? '') === '' ? 'recaptchaSiteKey' : 'recaptchaSecret';
            $errors[$missing] = 'Для каптчи нужны оба ключа: и ключ сайта, и секретный.';
        }

        return [$clean, $errors];
    }

    /**
     * Список из массива или из текста «по одному в строке».
     *
     * @return string[]
     */
    private static function lines(mixed $value): array
    {
        if (is_string($value)) {
            $value = preg_split('/[\r\n,]+/', $value) ?: [];
        }
        $list = [];
        foreach (is_array($value) ? $value : [] as $item) {
            if (is_string($item) && trim($item) !== '') {
                $list[] = trim($item);
            }
        }

        return array_values(array_unique($list));
    }
}
