<?php

declare(strict_types=1);

namespace Mitisk\Waf\Tests;

use Mitisk\Waf\Config;

/**
 * Настройки, сохранённые из панели управления (settings.php), перекрывают конфиг из index.php.
 */
final class AdminSettingsTest extends WafTestCase
{
    public function testWithoutSavedSettingsCodeConfigWorksAsBefore(): void
    {
        $config = Config::load(['runtimePath' => $this->runtime, 'blockDuration' => 600]);

        self::assertSame(600, $config->blockDuration);
        self::assertSame([], $config->overridden);
    }

    public function testSavedSettingsOverrideCodeConfig(): void
    {
        $this->storage()->writeSettings([
            'blockDuration' => 7200,
            'extraPatterns' => ['/old-cms/'],
            'disabledPatterns' => ['/login.php'],
            'allowIps' => ['203.0.113.0/24'],
        ]);
        $code = ['blockDuration' => 600];

        $this->assertPassed($this->request('/login.php', $code));
        $this->assertPassed($this->request('/old-cms/', $code, '203.0.113.9'), 'Белый список из панели');
        $response = $this->request('/old-cms/', $code);
        $this->assertBlocked($response);
        self::assertSame('7200', $response?->headers['Retry-After']);
    }

    public function testWafCanBeSwitchedOffFromPanel(): void
    {
        $this->storage()->writeSettings(['enabled' => false]);

        $this->assertPassed($this->request('/wp-login.php'));
    }

    public function testPanelCannotChangeProxyTrustOrStoragePath(): void
    {
        $this->storage()->writeSettings([
            'trustedHeaders' => ['X-Forwarded-For'],
            'trustedProxies' => ['0.0.0.0/0'],
            'badPatterns' => ['/'],
            'runtimePath' => '/tmp/elsewhere',
            'matchQuery' => true,
        ]);

        $config = Config::load(['runtimePath' => $this->runtime]);

        self::assertSame([], $config->trustedHeaders);
        self::assertSame([], $config->trustedProxies);
        self::assertSame(Config::DEFAULT_PATTERNS, $config->basePatterns);
        self::assertFalse($config->matchQuery);
        self::assertStringStartsWith($this->runtime, $config->storageDir);
        self::assertSame([], $config->overridden);
    }

    public function testCodeCanForbidPanelSettings(): void
    {
        $this->storage()->writeSettings(['enabled' => false]);

        $this->assertBlocked($this->request('/wp-login.php', ['adminSettings' => false]));
    }

    public function testBrokenSettingsFileIsIgnored(): void
    {
        mkdir($this->runtime . '/waf_blocks');
        file_put_contents($this->runtime . '/waf_blocks/settings.php', "<?php exit; ?>\n{не json");

        $this->assertBlocked($this->request('/wp-login.php'));
    }

    public function testEmptyCaptchaKeyFromPanelRemovesCaptcha(): void
    {
        $this->storage()->writeSettings(['recaptchaSiteKey' => '', 'recaptchaSecret' => '']);

        $response = $this->request('/wp-login.php', ['recaptchaSiteKey' => 'k', 'recaptchaSecret' => 's']);

        self::assertStringNotContainsString('data-sitekey', (string) $response?->body);
    }
}
