<?php

declare(strict_types=1);

namespace Mitisk\Waf\Tests;

use PHPUnit\Framework\Attributes\DataProvider;

final class FirewallTest extends WafTestCase
{
    public function testOrdinaryRequestPasses(): void
    {
        $this->assertPassed($this->request('/catalog/?page=2'));
    }

    public function testScannerAddressBansIpForEveryPage(): void
    {
        $this->assertBlocked($this->request('/wp-login.php'));
        $this->assertBlocked($this->request('/'), 'После блокировки закрыт весь сайт');
        $this->assertPassed($this->request('/', [], '198.51.100.8'), 'Соседний адрес не заблокирован');
    }

    public function testBanExpiresAfterBlockDuration(): void
    {
        $this->request('/.env', ['blockDuration' => 3600]);

        $this->now += 3599;
        $this->assertBlocked($this->request('/', ['blockDuration' => 3600]));
        $this->now += 2;
        $this->assertPassed($this->request('/', ['blockDuration' => 3600]));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function harmlessAddresses(): array
    {
        return [
            'поиск по сайту' => ['/search?q=.env'],
            'возврат после входа' => ['/auth?return=/login.php'],
            'ссылка в параметре' => ['/go?url=https://example.com/wp-content/a.png'],
            'статья про phpunit' => ['/blog/testing-with-phpunit'],
            'статья про wp-admin' => ['/blog/how-to-protect-wp-admin'],
            'слово с .git внутри' => ['/blog/my.github-notes'],
            'слово с .env внутри' => ['/docs/dev.environment'],
            'well-known: менеджер паролей' => ['/.well-known/change-password'],
            'well-known: Let’s Encrypt' => ['/.well-known/acme-challenge/token'],
        ];
    }

    #[DataProvider('harmlessAddresses')]
    public function testHarmlessAddressIsNotBanned(string $uri): void
    {
        $this->assertPassed($this->request($uri));
        $this->assertPassed($this->request('/'), 'После безобидного запроса адрес не заблокирован');
    }

    /**
     * @return array<string, array{string}>
     */
    public static function scannerAddresses(): array
    {
        return [
            'env в корне' => ['/.env'],
            'env в подпапке' => ['/api/.env.local'],
            'git' => ['/.git/config'],
            'wordpress' => ['/wordpress/wp-admin/setup-config.php'],
            'wp-includes' => ['/wp-includes/wlwmanifest.xml'],
            'phpunit eval' => ['/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php'],
            'регистр' => ['/WP-LOGIN.PHP'],
            'закодированная точка' => ['/%2eenv'],
            'двойное кодирование' => ['/%252egit/HEAD'],
            'с параметрами' => ['/xmlrpc.php?rsd'],
        ];
    }

    #[DataProvider('scannerAddresses')]
    public function testScannerAddressIsBanned(string $uri): void
    {
        $this->assertBlocked($this->request($uri));
    }

    public function testQueryStringIsMatchedOnlyWhenAsked(): void
    {
        $this->assertBlocked($this->request('/auth?return=/login.php', ['matchQuery' => true]));
    }

    public function testCustomBaseListReplacesDefaults(): void
    {
        $config = ['badPatterns' => ['/secret-admin']];

        $this->assertPassed($this->request('/wp-login.php', $config));
        $this->assertBlocked($this->request('/secret-admin/', $config));
    }

    public function testExtraAndDisabledPatterns(): void
    {
        $config = ['extraPatterns' => ['/old-cms/'], 'disabledPatterns' => ['/login.php']];

        $this->assertPassed($this->request('/login.php', $config), 'Выключенный шаблон не срабатывает');
        $this->assertBlocked($this->request('/old-cms/index.php', $config));
    }

    public function testTooShortPatternIsIgnored(): void
    {
        $this->assertPassed($this->request('/', ['extraPatterns' => ['/', 'a']]));
    }

    public function testDisabledWafPassesEverything(): void
    {
        $this->assertPassed($this->request('/wp-login.php', ['enabled' => false]));
    }

    public function testAllowListedIpIsNeverCheckedOrBlocked(): void
    {
        $config = ['allowIps' => ['198.51.100.0/24']];
        $this->request('/wp-login.php');

        $this->assertPassed($this->request('/', $config), 'Адрес из белого списка проходит даже с блокировкой');
        $this->assertPassed($this->request('/wp-login.php', $config));
        self::assertCount(1, $this->storage()->allBlocks($this->now), 'Новых блокировок не появилось');
    }

    public function testObserveModeLogsButDoesNotBlock(): void
    {
        $config = ['observeOnly' => true];

        $this->assertPassed($this->request('/wp-login.php', $config));
        $this->assertPassed($this->request('/', $config));
        self::assertSame([], $this->storage()->allBlocks($this->now));
        self::assertSame('observe', $this->storage()->events()[0]['action']);
    }

    public function testCrossSiteRequestGets404WithoutBan(): void
    {
        // <img src="https://site/wp-login.php"> на чужой странице: браузер посетителя шлёт запрос сам
        $response = $this->request('/wp-login.php', [], self::IP, ['HTTP_SEC_FETCH_SITE' => 'cross-site']);

        self::assertSame(404, $response?->status);
        $this->assertPassed($this->request('/'), 'Посетитель не заблокирован');
        self::assertSame('cross-site', $this->storage()->events()[0]['note']);
    }

    public function testCrossSiteProtectionCanBeTurnedOff(): void
    {
        $response = $this->request('/wp-login.php', ['skipCrossSite' => false], self::IP, ['HTTP_SEC_FETCH_SITE' => 'cross-site']);

        $this->assertBlocked($response);
    }

    public function testVerifiedSearchBotGets404WithoutBan(): void
    {
        $this->reverseDns['66.249.66.1'] = 'crawl-66-249-66-1.googlebot.com';
        $this->forwardDns['crawl-66-249-66-1.googlebot.com'] = ['66.249.66.1'];
        $googlebot = ['HTTP_USER_AGENT' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'];

        $response = $this->request('/wp-login.php', [], '66.249.66.1', $googlebot);

        self::assertSame(404, $response?->status);
        $this->assertPassed($this->request('/', [], '66.249.66.1', $googlebot));
    }

    public function testFakeBotIsBanned(): void
    {
        $googlebot = ['HTTP_USER_AGENT' => 'Googlebot/2.1'];
        // Нет обратной записи
        $this->assertBlocked($this->request('/wp-login.php', [], '203.0.113.50', $googlebot));
        // Обратная запись в чужом домене
        $this->reverseDns['203.0.113.51'] = 'googlebot.com.evil.example';
        $this->assertBlocked($this->request('/wp-login.php', [], '203.0.113.51', $googlebot));
        // Имя в домене Google, но прямая запись указывает на другой адрес
        $this->reverseDns['203.0.113.52'] = 'crawl.googlebot.com';
        $this->forwardDns['crawl.googlebot.com'] = ['66.249.66.1'];
        $this->assertBlocked($this->request('/wp-login.php', [], '203.0.113.52', $googlebot));
    }

    public function testPermanentBanNeverExpires(): void
    {
        $config = ['permanentBlock' => true];
        $response = $this->request('/wp-login.php', $config);

        self::assertStringContainsString('свяжитесь с администратором', (string) $response?->body);
        self::assertArrayNotHasKey('Retry-After', (array) $response?->headers);
        $this->now += 400 * 86400;
        $this->maintenanceDue = true;
        $this->assertBlocked($this->request('/', $config));
    }

    public function testIpv6NeighboursShareOneBan(): void
    {
        $this->assertBlocked($this->request('/wp-login.php', [], '2001:db8:1:2::1'));

        $this->assertBlocked($this->request('/', [], '2001:db8:1:2:aaaa::9'), 'Адрес из той же сети /64');
        $this->assertPassed($this->request('/', [], '2001:db8:1:3::1'), 'Соседняя сеть');
        self::assertCount(1, $this->storage()->allBlocks($this->now));
    }

    public function testSpoofedForwardedForDoesNotBanSomeoneElse(): void
    {
        $config = ['trustedHeaders' => ['X-Forwarded-For'], 'trustedProxies' => ['10.0.0.0/8']];
        $server = ['HTTP_X_FORWARDED_FOR' => '66.249.66.1, ' . self::IP];

        $this->request('/wp-login.php', $config, '10.0.0.2', $server);

        $blocks = $this->storage()->allBlocks($this->now);
        self::assertSame([self::IP], array_column($blocks, 'ip'));
    }

    public function testBanRecordSaysWhoWhenAndWhy(): void
    {
        $this->request('/WP-Login.php?x=1', [], self::IP, ['HTTP_USER_AGENT' => 'dirsearch/0.4']);

        $block = $this->storage()->allBlocks($this->now)[0];
        self::assertSame(self::IP, $block['ip']);
        self::assertSame(self::START, $block['at']);
        self::assertSame(self::START + 86400, $block['until']);
        self::assertSame('/WP-Login.php?x=1', $block['uri']);
        self::assertSame('/wp-login', $block['pattern']);
        self::assertSame('dirsearch/0.4', $block['ua']);

        $event = $this->storage()->events()[0];
        self::assertSame('ban', $event['action']);
        self::assertSame(self::IP, $event['ip']);
    }

    public function testLongBanSurvivesCleanup(): void
    {
        $config = ['blockDuration' => 7 * 86400];
        $this->request('/wp-login.php', $config);

        $this->now += 3 * 86400;
        $this->maintenanceDue = true;
        $this->assertPassed($this->request('/', $config, '203.0.113.9'), 'Чужой запрос запускает уборку');

        $this->assertBlocked($this->request('/', $config), 'Блокировка на 7 дней пережила уборку на третий день');
    }

    public function testCleanupRemovesExpiredBansOfVisitorsWhoNeverReturned(): void
    {
        $this->request('/wp-login.php');
        $this->now += 2 * 86400;
        $this->maintenanceDue = true;

        $this->request('/', [], '203.0.113.9');

        self::assertSame([], glob($this->runtime . '/waf_blocks/block_*.php'));
    }

    public function testStorageFailureDoesNotBreakTheSite(): void
    {
        // runtimePath указывает на файл: папку создать нельзя
        file_put_contents($this->runtime . '/not-a-dir', 'x');
        $config = ['runtimePath' => $this->runtime . '/not-a-dir'];

        $this->assertPassed($this->request('/', $config));
        $this->assertBlocked($this->request('/wp-login.php', $config), 'Сам запрос сканера отбит и без хранилища');
    }

    public function testLegacyPermanentBansAreImported(): void
    {
        mkdir($this->runtime . '/waf_blocks');
        file_put_contents($this->runtime . '/waf_blocks/banned_ips.json', json_encode([self::IP, '203.0.113.77']));

        $this->assertBlocked($this->request('/', ['permanentBlock' => true]));

        self::assertFileDoesNotExist($this->runtime . '/waf_blocks/banned_ips.json');
        self::assertCount(2, $this->storage()->allBlocks($this->now));
    }
}
