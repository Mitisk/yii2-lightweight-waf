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
- **Поддержка Google reCAPTCHA v2:** Злоумышленник (или реальный пользователь, случайно попавший в список) получает заглушку с каптчей для разблокировки адреса.
- **Автоочистка:** Старые файлы блокировок (старше 2 дней) автоматически удаляются.
- **Защита от IP-спуфинга:** По умолчанию используется только `REMOTE_ADDR`, доверенные заголовки настраиваются явно.

## Установка

Подключите пакет через Composer:

```bash
composer require mitisk/yii2-lightweight-waf
```

> **Совет:** Если пакет еще не опубликован на Packagist, вы можете установить его локально, указав репозиторий в вашем `composer.json`.

## Конфигурация и использование

Откройте ваш основной файл точки входа `web/index.php`. Вам нужно добавить инициализацию WAF **после** загрузки автолоадера composer, но **до** инициализации Yii2.

Пример интеграции в `web/index.php`:

```php
<?php

// 1. Подключаем Composer автолоадер (обязательно до WAF!)
require __DIR__ . '/../vendor/autoload.php';

// 2. Инициализируем и запускаем WAF передавая конфигурацию
\Mitisk\Waf\LightweightWaf::run([
    // Обязательные параметры:
    'runtimePath'      => __DIR__ . '/../runtime',
    'recaptchaSiteKey' => 'ВАШ_SITE_KEY',   // Site Key от Google reCAPTCHA v2
    'recaptchaSecret'  => 'ВАШ_SECRET_KEY', // Secret Key от Google reCAPTCHA v2

    // ОПЦИОНАЛЬНЫЕ ПАРАМЕТРЫ:
    // 'blockDuration'  => 86400,   // Время блокировки в секундах (по умолчанию 24 часа)
    // 'trustedHeaders' => ['X-Forwarded-For', 'X-Real-IP'], // Заголовки для определения IP за прокси
    // 'badPatterns'    => [        // Массив подозрительных путей
    //     '/admin.php',
    //     '/wp-login.php',
    //     '/.env',
    //     '/bitrix/admin',
    //     '/.git'
    // ]
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
| `recaptchaSiteKey` | `string` | да | — | Site Key от Google reCAPTCHA v2 |
| `recaptchaSecret` | `string` | да | — | Secret Key от Google reCAPTCHA v2 |
| `blockDuration` | `int` | нет | `86400` | Время блокировки IP в секундах (24 часа) |
| `trustedHeaders` | `array` | нет | `[]` | Заголовки для определения IP за прокси (например `['X-Forwarded-For']`) |
| `badPatterns` | `array` | нет | *встроенный список* | Массив подозрительных URI-паттернов для блокировки |

### trustedHeaders

По умолчанию WAF определяет IP клиента только через `REMOTE_ADDR` — это защищает от спуфинга через заголовки. Если ваш сайт работает за reverse-proxy (Nginx, Cloudflare), укажите доверенные заголовки:

```php
'trustedHeaders' => ['X-Forwarded-For', 'X-Real-IP'],
```

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

1. При каждом запросе WAF проверяет URI на совпадение с путями из массива `badPatterns`.
2. Если совпадение найдено, IP-адрес пользователя заносится во временный локальный файл.
3. Всем заблокированным IP возвращается статус `403 Forbidden` и выводится легковесная страница с Google reCAPTCHA v2.
4. После успешного прохождения каптчи IP удаляется из блэклиста и пользователь перенаправляется на главную страницу (редирект `/`).
5. Файлы блокировок старше 2 дней автоматически удаляются (вероятностная очистка, ~1 из 50 запросов).

## Требования
- PHP >= 7.4
- Права на запись в папку `runtime` (или путь, переданный в конфиге).

## Лицензия
MIT
