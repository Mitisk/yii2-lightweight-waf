# Yii2 Lightweight WAF

[![Latest Stable Version](https://poser.pugx.org/mitisk/yii2-lightweight-waf/v/stable)](https://packagist.org/packages/mitisk/yii2-lightweight-waf)
[![Total Downloads](https://poser.pugx.org/mitisk/yii2-lightweight-waf/downloads)](https://packagist.org/packages/mitisk/yii2-lightweight-waf)
[![License](https://poser.pugx.org/mitisk/yii2-lightweight-waf/license)](https://packagist.org/packages/mitisk/yii2-lightweight-waf)
[![PHP Version](https://img.shields.io/packagist/php-v/mitisk/yii2-lightweight-waf)](https://packagist.org/packages/mitisk/yii2-lightweight-waf)
[![GitHub Issues](https://img.shields.io/github/issues/Mitisk/yii2-lightweight-waf)](https://github.com/Mitisk/yii2-lightweight-waf/issues)
[![GitHub Stars](https://img.shields.io/github/stars/Mitisk/yii2-lightweight-waf)](https://github.com/Mitisk/yii2-lightweight-waf)

Легковесный Web Application Firewall (WAF) для защиты проектов на Yii2 от ботов и сканеров уязвимостей (dirsearch, wp-scanners и прочих).

Этот скрипт запускается до инициализации тяжелого ядра Yii2. Это позволяет отбивать запросы злоумышленников за долю секунды, не нагружая БД и экономя оперативную память сервера.

## Особенности
- **Ранний запуск:** Интегрируется напрямую в `index.php` (до загрузки ядра Yii2).
- **Файловый кэш блокировок:** Заблокированные IP хранятся в файлов кеше, что увеличивает производительность ответа во время агрессивного сканирования.
- **Опциональная Google reCAPTCHA v2:** Если ключи указаны — пользователь может снять блокировку, пройдя каптчу. Если не указаны — показывается статичная страница 403.
- **Два режима блокировки:** временная (на `blockDuration` секунд) или перманентная (IP навсегда попадает в `banned_ips.json`).
- **Автоочистка:** Старые файлы временных блокировок (старше 2 дней) автоматически удаляются.
- **Защита от IP-спуфинга:** По умолчанию используется только `REMOTE_ADDR`, доверенные заголовки настраиваются явно.

## Установка

Подключите пакет через Composer:

```bash
composer require mitisk/yii2-lightweight-waf
```

## Конфигурация и использование

Откройте ваш основной файл точки входа `web/index.php`. Вам нужно добавить инициализацию WAF **после** загрузки автолоадера composer, но **до** инициализации Yii2.

Пример интеграции в `web/index.php`:

```php
<?php

// 1. Подключаем Composer автолоадер (обязательно до WAF!)
require __DIR__ . '/../vendor/autoload.php';

// 2. Инициализируем и запускаем WAF передавая конфигурацию
\Mitisk\Waf\LightweightWaf::run([
    // Обязательный параметр:
    'runtimePath'      => __DIR__ . '/../runtime',

    // ОПЦИОНАЛЬНЫЕ ПАРАМЕТРЫ:
    // 'recaptchaSiteKey' => 'ВАШ_SITE_KEY',   // Site Key от Google reCAPTCHA v2
    // 'recaptchaSecret'  => 'ВАШ_SECRET_KEY', // Secret Key от Google reCAPTCHA v2
    // 'permanentBlock'   => false, // true = блокировать IP навсегда в banned_ips.json
    // 'blockDuration'    => 86400, // Время временной блокировки в секундах (по умолчанию 24 часа)
    // 'trustedHeaders'   => ['X-Forwarded-For', 'X-Real-IP'], // Заголовки для определения IP за прокси
    // 'trustedProxies'   => ['10.0.0.0/8', '172.16.0.0/12'],  // CIDR/IP доверенных прокси (обязательно при использовании trustedHeaders)
    // 'captchaMaxAttempts' => 5,   // Максимум неудачных попыток каптчи в окне
    // 'captchaWindow'    => 600,   // Длина окна попыток каптчи в секундах
    // 'badPatterns'      => [      // Массив подозрительных путей
    //     '/admin.php',
    //     '/wp-login.php',
    //     '/.env',
    //     '/bitrix/admin',
    //     '/.git',
    // ],
]);

// 3. Стандартная загрузка Yii2
defined('YII_DEBUG') or define('YII_DEBUG', true);
defined('YII_ENV') or define('YII_ENV', 'dev');

require __DIR__ . '/../vendor/yiisoft/yii2/Yii.php';

$config = require __DIR__ . '/../config/web.php';

(new yii\web\Application($config))->run();
```

> **Важно:** Папка, переданная в `runtimePath`, должна быть доступна для записи веб-серверу (в ней будет создана директория `waf_blocks` для хранения файлов блокировок).

## Параметры конфигурации

| Параметр | Тип | Обязательный | По умолчанию | Описание |
|---|---|---|---|---|
| `runtimePath` | `string` | да | — | Путь до папки runtime |
| `recaptchaSiteKey` | `string` | нет | `null` | Site Key от Google reCAPTCHA v2. Если не задан — страница разблокировки с каптчей не показывается |
| `recaptchaSecret` | `string` | нет | `null` | Secret Key от Google reCAPTCHA v2. Если не задан — страница разблокировки с каптчей не показывается |
| `permanentBlock` | `bool` | нет | `false` | Блокировать IP навсегда в общем файле `banned_ips.json` вместо таймера |
| `blockDuration` | `int` | нет | `86400` | Время временной блокировки IP в секундах (24 часа). Игнорируется при `permanentBlock=true` |
| `trustedHeaders` | `array` | нет | `[]` | Заголовки для определения IP за прокси (например `['X-Forwarded-For']`). Игнорируются, если не задан `trustedProxies` |
| `trustedProxies` | `array` | нет | `[]` | IP или CIDR доверенных прокси, от которых принимаются `trustedHeaders` (например `['10.0.0.0/8', '172.16.0.0/12']`). Поддерживаются IPv4 и IPv6 |
| `captchaMaxAttempts` | `int` | нет | `5` | Максимум неудачных попыток каптчи в окне `captchaWindow`. После превышения — каптча скрывается, показывается статичная страница 403 |
| `captchaWindow` | `int` | нет | `600` | Длина окна попыток каптчи в секундах |
| `badPatterns` | `array` | нет | *встроенный список* | Массив подозрительных URI-паттернов для блокировки |

### Опциональная reCAPTCHA

Если `recaptchaSiteKey` и `recaptchaSecret` заданы — заблокированному пользователю показывается форма с каптчей, пройдя которую он снимает блокировку с своего IP.

Если ключи не заданы — показывается статичная страница 403 без возможности саморазблокировки:
- при временной блокировке — с указанием точного времени разблокировки;
- при перманентной блокировке — с просьбой связаться с администратором.

### permanentBlock

В обычном режиме (`false`) каждый заблокированный IP хранится в отдельном файле `runtime/waf_blocks/block_<md5>.txt` с истекающим таймером.

В режиме `true` все забаненные IP пишутся в один файл `runtime/waf_blocks/banned_ips.json` (JSON-массив строк) и остаются там навсегда. Запись происходит под эксклюзивным `flock()`, так что параллельные запросы не повредят файл.

Пример содержимого `banned_ips.json`:
```json
["203.0.113.42", "198.51.100.7"]
```

Чтобы вручную разбанить IP — просто отредактируйте этот файл. Для полного сброса — удалите его.

### trustedHeaders и trustedProxies

По умолчанию WAF определяет IP клиента только через `REMOTE_ADDR` — это защищает от спуфинга через заголовки. Если ваш сайт работает за reverse-proxy (Nginx, Cloudflare), укажите доверенные заголовки **и** список доверенных прокси:

```php
'trustedHeaders' => ['X-Forwarded-For', 'X-Real-IP'],
'trustedProxies' => ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
```

> **Важно:** `trustedHeaders` без `trustedProxies` игнорируется (с записью предупреждения в `error_log`). Это защита от ситуации, когда злоумышленник ходит к PHP в обход прокси и подделывает заголовок. WAF читает заголовок только если `REMOTE_ADDR` входит в один из CIDR-диапазонов `trustedProxies`.

### Лимит попыток каптчи

Чтобы заблокированный бот не мог бесконечно дёргать форму с reCAPTCHA, действует лимит: после `captchaMaxAttempts` неудачных попыток в окне `captchaWindow` (по умолчанию 5 попыток за 10 минут) каптча больше не показывается этому IP — выводится статичная страница 403 с сообщением о времени разблокировки. Окно сбрасывается автоматически по истечении `captchaWindow`.

### Сетевые запросы

Для верификации reCAPTCHA WAF предпочитает cURL (если доступен), с автоматическим fallback на `file_get_contents` со stream context — это покрывает хостинги, где `allow_url_fopen=Off`.

## Расширенные настройки

Вы можете передавать любой набор паттернов через параметр `badPatterns`. По умолчанию WAF блокирует:
- `/admin.php`
- `/wp-login.php`
- `/wp-admin`
- `/.env`
- `/xmlrpc.php`
- `/bitrix/admin`
- `/.git`
- `/config.json`
- `/phpunit.xml`

## Как это работает?

1. При каждом запросе WAF сравнивает URI с паттернами из `badPatterns`.
2. Если совпадение найдено — IP вносится в блэклист:
   - `permanentBlock=false`: создаётся файл `block_<md5(ip)>.txt` с timestamp истечения блокировки;
   - `permanentBlock=true`: IP добавляется в общий `banned_ips.json` (атомарно, под `flock LOCK_EX`).
3. Заблокированным IP возвращается `403 Forbidden`. Что именно они увидят — зависит от конфигурации:
   - **Ключи reCAPTCHA заданы** → форма с каптчей. После прохождения IP снимается с блокировки и пользователь редиректится на `/`.
   - **Ключи не заданы** → статичная страница 403: с временем разблокировки (временный режим) или просьбой связаться с администратором (перманентный режим).
4. Временные файлы блокировок старше 2 дней автоматически удаляются (вероятностная очистка, ~1 из 50 запросов). В режиме `permanentBlock` очистка не выполняется.

## Требования
- PHP >= 8.1
- Права на запись в папку `runtime` (или путь, переданный в конфиге).
- Опционально: расширение `curl` (для верификации reCAPTCHA — иначе используется `file_get_contents` через stream context).

## Лицензия
MIT
