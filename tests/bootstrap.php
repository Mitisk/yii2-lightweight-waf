<?php

declare(strict_types=1);

// Пакет без зависимостей: достаточно своего автозагрузчика (vendor/ может и не быть).
spl_autoload_register(static function (string $class): void {
    $map = [
        'Mitisk\\Waf\\Tests\\' => __DIR__ . '/',
        'Mitisk\\Waf\\' => __DIR__ . '/../src/',
    ];
    foreach ($map as $prefix => $dir) {
        if (str_starts_with($class, $prefix)) {
            $file = $dir . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
            if (is_file($file)) {
                require $file;
            }
            return;
        }
    }
});
