<?php

declare(strict_types=1);

namespace Mitisk\Waf;

/**
 * Настройки из панели управления не прошли проверку. Ничего не сохранено.
 */
final class SettingsException extends \InvalidArgumentException
{
    /**
     * @param array<string, string> $errors ключ настройки → сообщение
     */
    public function __construct(public readonly array $errors)
    {
        parent::__construct(implode(' ', $errors));
    }
}
