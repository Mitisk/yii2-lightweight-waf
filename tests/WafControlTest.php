<?php

declare(strict_types=1);

namespace Mitisk\Waf\Tests;

use Mitisk\Waf\SettingsException;
use Mitisk\Waf\WafControl;

/**
 * Управление WAF из панели администратора.
 */
final class WafControlTest extends WafTestCase
{
    private function control(): WafControl
    {
        return new WafControl($this->runtime . DIRECTORY_SEPARATOR . 'waf_blocks', fn (): int => $this->now);
    }

    public function testSavedSettingsAreAppliedToNextRequest(): void
    {
        $saved = $this->control()->saveSettings([
            'observeOnly' => '1',
            'blockDuration' => '7200',
            'extraPatterns' => [' /Old-CMS/ ', '/old-cms/'],
            'allowIps' => ['203.0.113.0/24'],
        ]);

        self::assertTrue($saved['observeOnly']);
        self::assertSame(7200, $saved['blockDuration']);
        self::assertSame(['/old-cms/'], $saved['extraPatterns']);
        self::assertSame($saved, $this->control()->settings());
        $this->assertPassed($this->request('/wp-login.php'), 'Режим наблюдения из панели действует');
    }

    public function testUnknownAndCodeOnlyKeysAreDropped(): void
    {
        $saved = $this->control()->saveSettings(['enabled' => true, 'trustedProxies' => ['0.0.0.0/0'], 'runtimePath' => '/x']);

        self::assertSame(['enabled' => true], $saved);
    }

    public function testInvalidSettingsAreRejectedWithAllErrors(): void
    {
        try {
            $this->control()->saveSettings([
                'allowIps' => ['10.0.0.0/8', 'офис'],
                'extraPatterns' => ['a'],
                'blockDuration' => 5,
                'recaptchaSiteKey' => 'key-without-secret',
            ]);
            self::fail('Неверные настройки сохранились');
        } catch (SettingsException $e) {
            self::assertCount(4, $e->errors);
            self::assertArrayHasKey('allowIps', $e->errors);
            self::assertArrayHasKey('extraPatterns', $e->errors);
            self::assertArrayHasKey('blockDuration', $e->errors);
            self::assertArrayHasKey('recaptchaSecret', $e->errors);
        }
        self::assertSame([], $this->control()->settings(), 'Ничего не записано');
    }

    public function testPatternThatWouldBlockSafePathIsRejected(): void
    {
        $this->expectException(SettingsException::class);

        $this->control()->saveSettings(['extraPatterns' => ['/adm']], ['/', '/admin/waf/']);
    }

    public function testResetReturnsToCodeConfig(): void
    {
        $control = $this->control();
        $control->saveSettings(['enabled' => false]);

        $control->resetSettings();

        self::assertSame([], $control->settings());
        $this->assertBlocked($this->request('/wp-login.php'));
    }

    public function testBlocksListAndUnblock(): void
    {
        $this->request('/wp-login.php', [], '203.0.113.1');
        $this->now += 10;
        $this->request('/.env', [], '2001:db8:1:2::5');
        $control = $this->control();

        $blocks = $control->blocks();
        self::assertSame(['2001:db8:1:2::5', '203.0.113.1'], array_column($blocks, 'ip'), 'Новые первыми');
        self::assertSame('2001:db8:1:2::/64', $blocks[0]['key']);

        self::assertTrue($control->unblock('2001:db8:1:2::/64'), 'Снятие по ключу сети');
        self::assertTrue($control->unblock('203.0.113.1'));
        self::assertFalse($control->unblock('203.0.113.1'), 'Повторно снимать нечего');
        $this->assertPassed($this->request('/', [], '203.0.113.1'));
        self::assertSame('unban', $control->events(1)[0]['action']);
    }

    public function testManualBlock(): void
    {
        $control = $this->control();

        $block = $control->block('203.0.113.9', 3600, 'спам в формах');

        self::assertSame($this->now + 3600, $block['until']);
        self::assertSame('manual', $block['reason']);
        $this->assertBlocked($this->request('/', [], '203.0.113.9'));

        $forever = $control->block('203.0.113.10', null);
        self::assertSame(0, $forever['until']);
    }

    public function testManualBlockRejectsGarbage(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->control()->block('не адрес', 3600);
    }

    public function testStatsCountBansPerDay(): void
    {
        $this->request('/wp-login.php', [], '203.0.113.1');
        $this->request('/wp-login.php', [], '203.0.113.2');
        $this->now += 86400;
        $this->request('/wp-login.php', [], '203.0.113.3');
        $this->request('/wp-login.php', [], '203.0.113.4', ['HTTP_SEC_FETCH_SITE' => 'cross-site']);

        $stats = $this->control()->stats(7);

        self::assertSame(3, $stats['bans']);
        self::assertSame(1, $stats['active'], 'Вчерашние блокировки на сутки уже истекли');
        self::assertCount(7, $stats['byDay']);
        self::assertSame(1, $stats['byDay'][date('Y-m-d', $this->now)]);
        self::assertSame(2, $stats['byDay'][date('Y-m-d', $this->now - 86400)]);
    }

    public function testCheckTellsWhichPatternWouldFire(): void
    {
        $control = $this->control();
        $control->saveSettings(['extraPatterns' => ['/old-cms/'], 'disabledPatterns' => ['/login.php']]);

        self::assertSame('/old-cms/', $control->check('/old-cms/index.php'));
        self::assertNull($control->check('/login.php'));
        self::assertNull($control->check('/catalog/?q=.env'));
        self::assertSame('/secret', $control->check('/secret/x', ['badPatterns' => ['/secret']]));
    }

    public function testCurrentUsesRuntimePathWhenWafDidNotRunInThisProcess(): void
    {
        $control = WafControl::current($this->runtime);

        self::assertSame($this->runtime . DIRECTORY_SEPARATOR . 'waf_blocks', $control?->storageDir());
        self::assertNull(WafControl::current());
    }
}
