<?php

declare(strict_types=1);

namespace Mitisk\Waf\Tests;

/**
 * LightweightWaf::run() как в web/index.php: отдельный процесс PHP, потому что блокировка — это exit.
 */
final class EntryPointTest extends WafTestCase
{
    public function testCleanRequestReachesApplication(): void
    {
        self::assertSame('APP', $this->runIndex('/catalog/'));
    }

    public function testScannerRequestNeverReachesApplication(): void
    {
        $output = $this->runIndex('/wp-login.php');

        self::assertStringContainsString('Доступ временно ограничен', $output);
        self::assertStringNotContainsString('APP', $output);
        self::assertStringContainsString('временно ограничен', $this->runIndex('/'), 'Следующий запрос тоже закрыт');
    }

    public function testOldStyleConfigStillWorks(): void
    {
        $config = "['runtimePath' => \$argv[2], 'badPatterns' => ['/secret'], 'blockDuration' => 60, 'permanentBlock' => false, "
            . "'trustedHeaders' => [], 'trustedProxies' => [], 'captchaMaxAttempts' => 5, 'captchaWindow' => 600]";

        self::assertSame('APP', $this->runIndex('/wp-login.php', $config));
        self::assertStringContainsString('ограничен', $this->runIndex('/secret', $config));
    }

    public function testStorageDirIsKnownAfterRun(): void
    {
        $output = $this->runIndex('/', null, 'echo \Mitisk\Waf\LightweightWaf::storageDir();');

        self::assertStringEndsWith('waf_blocks', $output);
    }

    private function runIndex(string $uri, ?string $config = null, string $app = "echo 'APP';"): string
    {
        $config ??= "['runtimePath' => \$argv[2]]";
        $script = $this->runtime . '/index.php';
        file_put_contents($script, '<?php'
            . ' require ' . var_export(__DIR__ . '/bootstrap.php', true) . ';'
            . ' $_SERVER["REMOTE_ADDR"] = "198.51.100.7"; $_SERVER["REQUEST_METHOD"] = "GET";'
            . ' $_SERVER["REQUEST_URI"] = $argv[1];'
            . ' \Mitisk\Waf\LightweightWaf::run(' . $config . ');'
            . ' ' . $app);

        $output = [];
        exec(
            escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($script) . ' ' . escapeshellarg($uri) . ' ' . escapeshellarg($this->runtime),
            $output
        );

        return implode("\n", $output);
    }
}
