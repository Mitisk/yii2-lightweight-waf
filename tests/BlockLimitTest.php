<?php

declare(strict_types=1);

namespace Mitisk\Waf\Tests;

use Mitisk\Waf\LightweightWaf;
use Mitisk\Waf\SettingsException;
use Mitisk\Waf\WafControl;

/**
 * Потолок числа блокировок, счётчик, постраничный список и «снять все».
 */
final class BlockLimitTest extends WafTestCase
{
    private function control(): WafControl
    {
        return new WafControl($this->runtime . '/waf_blocks', fn (): int => $this->now);
    }

    /** Банит $count разных адресов, по одному в минуту. Возвращает адреса в порядке блокировки. */
    private function banMany(int $count, array $config = []): array
    {
        $ips = [];
        for ($i = 1; $i <= $count; $i++) {
            $this->now += 60;
            $ips[] = $ip = '203.0.113.' . $i;
            $this->request('/wp-login.php', $config, $ip);
        }

        return $ips;
    }

    public function testOldestBlocksAreDroppedWhenLimitIsExceeded(): void
    {
        $config = ['permanentBlock' => true, 'maxBlocks' => 10];

        $ips = $this->banMany(14, $config);

        self::assertLessThanOrEqual(10, $this->control()->blocksCount(), 'Список растёт без потолка');
        $this->assertBlocked($this->request('/', $config, end($ips)), 'Свежая блокировка должна остаться');
        $this->assertPassed($this->request('/', $config, $ips[0]), 'Самая старая блокировка должна уйти');
    }

    public function testTrimLeavesHeadroomSoItDoesNotRunOnEveryBan(): void
    {
        $config = ['permanentBlock' => true, 'maxBlocks' => 10];

        $this->banMany(11, $config);

        self::assertSame(9, $this->control()->blocksCount(), 'После уборки остаётся 90% потолка');
    }

    public function testManualBlocksAreNotDroppedByLimit(): void
    {
        $config = ['permanentBlock' => true, 'maxBlocks' => 10];
        $this->control()->block('198.51.100.200', null, 'вручную');

        $this->banMany(25, $config);

        $this->assertBlocked($this->request('/', $config, '198.51.100.200'), 'Ручная блокировка — решение администратора');
    }

    public function testZeroLimitMeansNoLimit(): void
    {
        $this->banMany(15, ['permanentBlock' => true, 'maxBlocks' => 0]);

        self::assertSame(15, $this->control()->blocksCount());
    }

    public function testCountIgnoresExpiredBlocks(): void
    {
        $this->banMany(3, ['blockDuration' => 600]);

        self::assertSame(3, $this->control()->blocksCount());
        $this->now += 3600;
        self::assertSame(0, $this->control()->blocksCount());
    }

    public function testBlocksAreListedByPages(): void
    {
        $ips = $this->banMany(7, ['blockDuration' => 86400]);
        $control = $this->control();

        $first = array_column($control->blocksPage(3, 0), 'ip');
        $second = array_column($control->blocksPage(3, 3), 'ip');
        $third = array_column($control->blocksPage(3, 6), 'ip');

        self::assertSame([$ips[6], $ips[5], $ips[4]], $first, 'Сначала те, что истекают позже всех, — самые свежие');
        self::assertCount(3, $second);
        self::assertCount(1, $third);
        self::assertCount(7, array_unique(array_merge($first, $second, $third)), 'Страницы не пересекаются и покрывают всё');
    }

    public function testUnblockAllKeepsManualBlocksByDefault(): void
    {
        $this->banMany(4);
        $control = $this->control();
        $control->block('198.51.100.200', null, 'вручную');

        $removed = $control->unblockAll();

        self::assertSame(4, $removed);
        self::assertSame(1, $control->blocksCount());
        $this->assertBlocked($this->request('/', [], '198.51.100.200'));
        self::assertSame('unban_all', $control->events(1)[0]['action']);
    }

    public function testUnblockAllCanRemoveManualBlocksToo(): void
    {
        $this->banMany(2);
        $control = $this->control();
        $control->block('198.51.100.200', null);

        self::assertSame(3, $control->unblockAll(false));
        self::assertSame(0, $control->blocksCount());
    }

    public function testStatsCountActiveBlocksWithoutReadingThem(): void
    {
        $this->banMany(3);

        self::assertSame(3, $this->control()->stats(7)['active']);
    }

    public function testLimitIsEditableFromAdminWithinBounds(): void
    {
        $control = $this->control();

        $control->saveSettings(['maxBlocks' => 500]);
        self::assertSame(500, $control->settings()['maxBlocks']);

        $control->saveSettings(['maxBlocks' => 0]);
        self::assertSame(0, $control->settings()['maxBlocks'], '0 — без потолка');

        $this->expectException(SettingsException::class);
        $control->saveSettings(['maxBlocks' => 5]);
    }

    public function testApiVersionAnnouncesNewMethods(): void
    {
        self::assertGreaterThanOrEqual(2, WafControl::API);
        self::assertSame('2.2.0', LightweightWaf::VERSION);
    }
}
