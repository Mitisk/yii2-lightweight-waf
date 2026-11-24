<?php

declare(strict_types=1);

namespace Mitisk\Waf\Tests;

use Mitisk\Waf\Storage;

final class StorageTest extends WafTestCase
{
    public function testDataFilesAnswer404WhenRequestedOverHttp(): void
    {
        $this->request('/wp-login.php', [], self::IP, ['HTTP_USER_AGENT' => '<?php echo "x"; ?>']);
        $this->storage()->writeSettings(['recaptchaSecret' => 'secret']);

        $files = array_merge(
            glob($this->runtime . '/waf_blocks/block_*.php') ?: [],
            [$this->runtime . '/waf_blocks/events.php', $this->runtime . '/waf_blocks/settings.php'],
        );
        self::assertCount(3, $files);
        foreach ($files as $file) {
            $content = (string) file_get_contents($file);
            self::assertStringStartsWith(Storage::GUARD, $content, basename($file));
            // После замка в файле нет ни одного «<»: PHP-тег из User-Agent не станет кодом
            self::assertStringNotContainsString('<', substr($content, strlen(Storage::GUARD)), basename($file));

            $output = [];
            exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($file), $output);
            self::assertSame('', implode('', $output), basename($file) . ' ничего не выводит при запуске');
        }
    }

    public function testStorageDirIsClosedForApache(): void
    {
        $this->request('/wp-login.php');

        self::assertStringContainsString('Require all denied', (string) file_get_contents($this->runtime . '/waf_blocks/.htaccess'));
    }

    public function testEventsAreReturnedNewestFirstAndRotated(): void
    {
        $storage = $this->storage();
        $storage->appendEvent(['time' => 1, 'action' => 'ban', 'ip' => '203.0.113.1']);
        $storage->appendEvent(['time' => 2, 'action' => 'ban', 'ip' => '203.0.113.2']);

        self::assertSame(['203.0.113.2', '203.0.113.1'], array_column($storage->events(), 'ip'));
        self::assertCount(1, $storage->events(1));

        // Журнал перерос лимит — уходит в events.1.php, новые события пишутся в свежий файл
        file_put_contents($this->runtime . '/waf_blocks/events.php', str_repeat(' ', Storage::EVENTS_MAX_BYTES + 1), FILE_APPEND);
        $storage->appendEvent(['time' => 3, 'action' => 'ban', 'ip' => '203.0.113.3']);

        self::assertFileExists($this->runtime . '/waf_blocks/events.1.php');
        self::assertSame(['203.0.113.3', '203.0.113.2', '203.0.113.1'], array_column($storage->events(), 'ip'));
        self::assertLessThan(1000, filesize($this->runtime . '/waf_blocks/events.php'));
    }

    public function testInvalidUtf8InRequestDoesNotLoseTheBan(): void
    {
        $this->request("/wp-login.php/\xff\xfe", [], self::IP, ['HTTP_USER_AGENT' => "bad\xff"]);

        self::assertCount(1, $this->storage()->allBlocks($this->now));
        $this->assertBlocked($this->request('/'));
    }

    public function testCleanupRunsAtMostOncePerHour(): void
    {
        $this->request('/wp-login.php');
        $storage = $this->storage();

        self::assertTrue($storage->cleanup($this->now));
        self::assertFalse($storage->cleanup($this->now + 3599));
        self::assertTrue($storage->cleanup($this->now + 3601));
    }

    public function testCleanupRemovesStaleCaptchaCountersAndOldFormatFiles(): void
    {
        $dir = $this->runtime . '/waf_blocks';
        mkdir($dir);
        file_put_contents($dir . '/captcha_old.txt', '3|1');
        file_put_contents($dir . '/block_old.txt', '123');
        file_put_contents($dir . '/captcha_fresh.txt', '1|1');
        touch($dir . '/captcha_old.txt', $this->now - 3 * 86400);
        touch($dir . '/block_old.txt', $this->now - 3 * 86400);
        touch($dir . '/captcha_fresh.txt', $this->now - 3600);

        $this->storage()->cleanup($this->now);

        self::assertFileDoesNotExist($dir . '/captcha_old.txt');
        self::assertFileDoesNotExist($dir . '/block_old.txt');
        self::assertFileExists($dir . '/captcha_fresh.txt');
    }
}
