<?php

declare(strict_types=1);

namespace Mitisk\Waf;

/**
 * Настройки WAF: значения по умолчанию, конфиг из web/index.php и поверх него — настройки,
 * сохранённые из панели управления (файл settings.php в папке хранилища).
 */
final class Config
{
    /**
     * Шаблоны по умолчанию: подстрока пути запроса (без учёта регистра).
     * Ведущий «/» отсекает совпадения внутри слов: /blog/about-wp-admin не блокируется.
     */
    public const DEFAULT_PATTERNS = [
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
        '/wp-login',
        '/wp-content',
        '/wp-admin',
        '/wp-cache',
        '/wp-includes',
        '/xmlrpc.php',
        '/config.json',
        '/phpunit/',
        '/phpunit.xml',
        'eval-stdin.php',
        '/.env',
        '/bitrix/admin',
        '/.git',
    ];

    /**
     * Что можно менять из панели управления. Путь хранилища и доверенные прокси — только в коде:
     * ошибка в них превращает всех посетителей в один адрес.
     */
    public const ADMIN_KEYS = [
        'enabled',
        'observeOnly',
        'permanentBlock',
        'blockDuration',
        'maxBlocks',
        'disabledPatterns',
        'extraPatterns',
        'allowIps',
        'recaptchaSiteKey',
        'recaptchaSecret',
        'captchaMaxAttempts',
        'captchaWindow',
        'skipCrossSite',
        'verifyBots',
    ];

    /** Шаблон короче не применяется: «/» или «a» заблокировали бы всех. */
    public const MIN_PATTERN_LENGTH = 3;

    public const MIN_BLOCK_DURATION = 60;

    /** Папка хранилища: <runtimePath>/waf_blocks. */
    public string $storageDir = '';

    public bool $enabled = true;

    /** Режим наблюдения: срабатывания пишутся в журнал, никто не блокируется. */
    public bool $observeOnly = false;

    public bool $permanentBlock = false;

    public int $blockDuration = 86400;

    /**
     * Потолок числа блокировок: когда их больше, самые старые автоматические удаляются
     * (ручные остаются). 0 — без потолка: при бессрочной блокировке список будет только расти.
     */
    public int $maxBlocks = 2000;

    /** @var string[] Базовый список: встроенный или badPatterns из кода */
    public array $basePatterns = self::DEFAULT_PATTERNS;

    /** @var string[] Выключенные шаблоны базового списка */
    public array $disabledPatterns = [];

    /** @var string[] Свои шаблоны в дополнение к базовому списку */
    public array $extraPatterns = [];

    /** @var string[] Белый список IP/CIDR: не проверяются и не блокируются */
    public array $allowIps = [];

    /** @var string[] */
    public array $trustedHeaders = [];

    /** @var string[] */
    public array $trustedProxies = [];

    public ?string $recaptchaSiteKey = null;

    public ?string $recaptchaSecret = null;

    public int $captchaMaxAttempts = 5;

    public int $captchaWindow = 600;

    /** Искать шаблоны и в параметрах запроса (как до версии 2.1). Даёт ложные срабатывания. */
    public bool $matchQuery = false;

    /** Запрос, пришедший со стороннего сайта (Sec-Fetch-Site: cross-site), получает 404 без блокировки. */
    public bool $skipCrossSite = true;

    /** Подтверждённые по DNS роботы Google, Яндекса и Bing получают 404 без блокировки. */
    public bool $verifyBots = true;

    public bool $logEvents = true;

    /** Применять настройки из панели управления (файл settings.php). */
    public bool $adminSettings = true;

    /** @var string[] Ключи, которые перекрыты настройками из панели управления */
    public array $overridden = [];

    /** @var string[]|null */
    private ?array $patterns = null;

    /**
     * Конфиг запроса: код + (если разрешено) сохранённые настройки панели управления.
     *
     * @param array<string, mixed> $config массив из LightweightWaf::run()
     */
    public static function load(array $config): self
    {
        $self = self::fromArray($config);
        if ($self->adminSettings && $self->storageDir !== '') {
            $saved = (new Storage($self->storageDir))->readSettings();
            if ($saved !== null) {
                $self->applyAdminSettings($saved);
            }
        }

        return $self;
    }

    /**
     * @param array<string, mixed> $config
     */
    public static function fromArray(array $config): self
    {
        $self = new self();
        if (!empty($config['runtimePath'])) {
            $self->storageDir = rtrim((string) $config['runtimePath'], '/\\') . DIRECTORY_SEPARATOR . 'waf_blocks';
        }
        if (!empty($config['badPatterns']) && is_array($config['badPatterns'])) {
            $self->basePatterns = self::stringList($config['badPatterns']);
        }
        foreach (['trustedHeaders', 'trustedProxies'] as $key) {
            if (!empty($config[$key]) && is_array($config[$key])) {
                $self->{$key} = self::stringList($config[$key]);
            }
        }
        foreach (['matchQuery', 'logEvents', 'adminSettings'] as $key) {
            if (isset($config[$key])) {
                $self->{$key} = (bool) $config[$key];
            }
        }
        $self->apply($config);

        return $self;
    }

    /**
     * Накладывает настройки панели управления (только ключи из ADMIN_KEYS).
     *
     * @param array<string, mixed> $settings
     */
    public function applyAdminSettings(array $settings): void
    {
        $settings = array_intersect_key($settings, array_flip(self::ADMIN_KEYS));
        $this->apply($settings);
        $this->overridden = array_keys($settings);
    }

    /**
     * Итоговый список шаблонов: базовый минус выключенные плюс свои, в нижнем регистре.
     *
     * @return string[]
     */
    public function patterns(): array
    {
        if ($this->patterns !== null) {
            return $this->patterns;
        }

        $disabled = array_map('strtolower', $this->disabledPatterns);
        $list = [];
        foreach (array_merge($this->basePatterns, $this->extraPatterns) as $index => $pattern) {
            $pattern = strtolower(trim($pattern));
            $isBase = $index < count($this->basePatterns);
            if (strlen($pattern) < self::MIN_PATTERN_LENGTH || ($isBase && in_array($pattern, $disabled, true))) {
                continue;
            }
            $list[$pattern] = true;
        }

        return $this->patterns = array_keys($list);
    }

    public function captchaConfigured(): bool
    {
        return $this->recaptchaSiteKey !== null && $this->recaptchaSecret !== null;
    }

    /**
     * @param array<string, mixed> $values
     */
    private function apply(array $values): void
    {
        foreach (['enabled', 'observeOnly', 'permanentBlock', 'skipCrossSite', 'verifyBots'] as $key) {
            if (isset($values[$key])) {
                $this->{$key} = (bool) $values[$key];
            }
        }
        if (isset($values['blockDuration'])) {
            $this->blockDuration = max(self::MIN_BLOCK_DURATION, (int) $values['blockDuration']);
        }
        if (isset($values['maxBlocks'])) {
            $this->maxBlocks = max(0, (int) $values['maxBlocks']);
        }
        if (isset($values['captchaMaxAttempts'])) {
            $this->captchaMaxAttempts = max(1, (int) $values['captchaMaxAttempts']);
        }
        if (isset($values['captchaWindow'])) {
            $this->captchaWindow = max(1, (int) $values['captchaWindow']);
        }
        foreach (['recaptchaSiteKey', 'recaptchaSecret'] as $key) {
            if (array_key_exists($key, $values)) {
                $value = trim((string) $values[$key]);
                $this->{$key} = $value === '' ? null : $value;
            }
        }
        foreach (['disabledPatterns', 'extraPatterns', 'allowIps'] as $key) {
            if (isset($values[$key]) && is_array($values[$key])) {
                $this->{$key} = self::stringList($values[$key]);
            }
        }
        $this->patterns = null;
    }

    /**
     * @param array<mixed> $items
     * @return string[]
     */
    private static function stringList(array $items): array
    {
        $list = [];
        foreach ($items as $item) {
            if (is_string($item) && trim($item) !== '') {
                $list[] = trim($item);
            }
        }

        return array_values(array_unique($list));
    }
}
