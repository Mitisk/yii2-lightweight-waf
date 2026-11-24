<?php

declare(strict_types=1);

namespace Mitisk\Waf\Tests;

use Mitisk\Waf\BotVerifier;
use Mitisk\Waf\Config;
use Mitisk\Waf\Firewall;
use Mitisk\Waf\Response;
use Mitisk\Waf\Storage;
use PHPUnit\Framework\TestCase;

/**
 * Основа тестов: временная папка runtime, управляемые часы, каптча и DNS без сети.
 */
abstract class WafTestCase extends TestCase
{
    protected const IP = '198.51.100.7';
    protected const START = 1_800_000_000;

    protected string $runtime;

    protected int $now = self::START;

    /** Ответ «каптча пройдена» для следующей проверки. */
    protected bool $captchaPasses = true;

    /** Пора ли запускать уборку в этом запросе. */
    protected bool $maintenanceDue = false;

    /** @var array<string, string> обратные DNS-записи: адрес → имя */
    protected array $reverseDns = [];

    /** @var array<string, string[]> прямые DNS-записи: имя → адреса */
    protected array $forwardDns = [];

    protected function setUp(): void
    {
        parent::setUp();
        $this->runtime = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'waf-test-' . bin2hex(random_bytes(6));
        mkdir($this->runtime, 0777, true);
    }

    protected function tearDown(): void
    {
        $this->removeDir($this->runtime);
        parent::tearDown();
    }

    /**
     * @param array<string, mixed> $config
     */
    protected function firewall(array $config = []): Firewall
    {
        return new Firewall(
            Config::load($config + ['runtimePath' => $this->runtime]),
            null,
            fn (): int => $this->now,
            fn (string $token, string $ip): bool => $this->captchaPasses,
            new BotVerifier(
                fn (string $ip): ?string => $this->reverseDns[$ip] ?? null,
                fn (string $host): array => $this->forwardDns[$host] ?? [],
            ),
            fn (): bool => $this->maintenanceDue,
        );
    }

    /**
     * Запрос к сайту.
     *
     * @param array<string, mixed> $config
     * @param array<string, mixed> $server дополнительные элементы $_SERVER
     * @param array<string, mixed>|null $post тело POST-запроса; null — GET
     */
    protected function request(string $uri, array $config = [], string $ip = self::IP, array $server = [], ?array $post = null): ?Response
    {
        $server += [
            'REMOTE_ADDR' => $ip,
            'REQUEST_URI' => $uri,
            'REQUEST_METHOD' => $post === null ? 'GET' : 'POST',
            'HTTP_USER_AGENT' => 'Mozilla/5.0 (scanner)',
        ];

        return $this->firewall($config)->handle($server, $post ?? []);
    }

    protected function storage(): Storage
    {
        return new Storage($this->runtime . DIRECTORY_SEPARATOR . 'waf_blocks');
    }

    protected function assertPassed(?Response $response, string $message = ''): void
    {
        self::assertNull($response, $message !== '' ? $message : 'Запрос должен был пройти в приложение');
    }

    protected function assertBlocked(?Response $response, string $message = ''): void
    {
        self::assertNotNull($response, $message !== '' ? $message : 'Запрос должен был быть заблокирован');
        self::assertSame(403, $response->status, $message);
    }

    private function removeDir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        foreach (scandir($dir) ?: [] as $name) {
            if ($name === '.' || $name === '..') {
                continue;
            }
            $path = $dir . DIRECTORY_SEPARATOR . $name;
            is_dir($path) ? $this->removeDir($path) : unlink($path);
        }
        rmdir($dir);
    }
}
