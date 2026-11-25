<?php

declare(strict_types=1);

namespace Mitisk\Waf;

/**
 * Lightweight WAF (Web Application Firewall)
 * Предназначен для защиты от автоматических сканеров уязвимостей (dirsearch, wp-scanners и др.)
 * Работает на раннем этапе загрузки до инициализации тяжелого ядра Yii2.
 *
 * Точка входа — run() в web/index.php. Решение по запросу принимает {@see Firewall},
 * настройки собирает {@see Config}, данные хранит {@see Storage}. Управление из панели
 * администратора — {@see WafControl}.
 */
class LightweightWaf
{
    public const VERSION = '2.2.0';

    /** Конфиг текущего запроса; null — run() не вызывался (консоль, WAF не подключён в index.php). */
    private static ?Config $config = null;

    /**
     * Точка входа для WAF. Вызывается в web/index.php.
     *
     * @param array<string, mixed> $config Конфигурационные параметры:
     * - runtimePath (string, required): Путь до папки runtime
     * - enabled (bool, optional): Выключить WAF, не убирая вызов (по умолчанию true)
     * - observeOnly (bool, optional): Режим наблюдения — писать срабатывания в журнал, не блокировать
     * - recaptchaSiteKey (string, optional): Публичный ключ каптчи
     * - recaptchaSecret (string, optional): Приватный ключ каптчи
     * - badPatterns (array, optional): Свой базовый список шаблонов вместо встроенного
     * - extraPatterns (array, optional): Шаблоны в дополнение к базовому списку
     * - disabledPatterns (array, optional): Выключенные шаблоны базового списка
     * - matchQuery (bool, optional): Искать шаблоны и в параметрах запроса (по умолчанию false)
     * - allowIps (array, optional): Белый список IP/CIDR — не проверяются и не блокируются
     * - blockDuration (int, optional): Время блокировки в секундах (по умолчанию 86400)
     * - permanentBlock (bool, optional): Блокировать навсегда (по умолчанию false)
     * - trustedHeaders (array, optional): Заголовки для определения IP за прокси
     * - trustedProxies (array, optional): IP или CIDR доверенных прокси, от которых принимаются trustedHeaders
     * - captchaMaxAttempts (int, optional): Максимум неудач каптчи в окне (по умолчанию 5)
     * - captchaWindow (int, optional): Длина окна попыток каптчи в секундах (по умолчанию 600)
     * - skipCrossSite (bool, optional): Запросам со сторонних сайтов — 404 без блокировки (по умолчанию true)
     * - verifyBots (bool, optional): Подтверждённым поисковым роботам — 404 без блокировки (по умолчанию true)
     * - logEvents (bool, optional): Вести журнал срабатываний (по умолчанию true)
     * - adminSettings (bool, optional): Применять настройки из панели управления (по умолчанию true)
     */
    public static function run(array $config): void
    {
        if (empty($config['runtimePath'])) {
            self::terminate('Configuration error.');
        }

        try {
            self::$config = Config::load($config);
            $response = (new Firewall(self::$config))->handle($_SERVER, $_POST);
        } catch (\Throwable $e) {
            // Ошибка самого WAF не должна ронять сайт: пропускаем запрос в приложение
            @error_log('[LightweightWaf] ' . $e::class . ': ' . $e->getMessage());
            return;
        }

        if ($response !== null) {
            $response->send();
            exit;
        }
    }

    /** Конфиг, с которым WAF отработал в этом запросе (с учётом настроек панели управления). */
    public static function config(): ?Config
    {
        return self::$config;
    }

    /** Папка хранилища этого запроса; null — run() не вызывался. */
    public static function storageDir(): ?string
    {
        return self::$config?->storageDir;
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
