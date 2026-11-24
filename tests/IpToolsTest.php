<?php

declare(strict_types=1);

namespace Mitisk\Waf\Tests;

use Mitisk\Waf\IpTools;
use PHPUnit\Framework\TestCase;

final class IpToolsTest extends TestCase
{
    private const HEADERS = ['X-Forwarded-For', 'X-Real-IP'];
    private const PROXIES = ['10.0.0.0/8'];

    public function testWithoutTrustedHeadersUsesRemoteAddr(): void
    {
        $ip = IpTools::clientIp(['REMOTE_ADDR' => '203.0.113.5', 'HTTP_X_FORWARDED_FOR' => '1.2.3.4'], [], []);

        self::assertSame('203.0.113.5', $ip);
    }

    public function testHeaderFromUntrustedRemoteIsIgnored(): void
    {
        $server = ['REMOTE_ADDR' => '203.0.113.5', 'HTTP_X_FORWARDED_FOR' => '1.2.3.4'];

        self::assertSame('203.0.113.5', IpTools::clientIp($server, self::HEADERS, self::PROXIES));
    }

    public function testClientCannotSpoofAddressThroughForwardedFor(): void
    {
        // Клиент 198.51.100.7 сам прислал «X-Forwarded-For: 8.8.8.8», nginx дописал его настоящий адрес
        $server = ['REMOTE_ADDR' => '10.0.0.2', 'HTTP_X_FORWARDED_FOR' => '8.8.8.8, 198.51.100.7'];

        self::assertSame('198.51.100.7', IpTools::clientIp($server, self::HEADERS, self::PROXIES));
    }

    public function testChainOfTrustedProxiesIsSkipped(): void
    {
        $server = ['REMOTE_ADDR' => '10.0.0.2', 'HTTP_X_FORWARDED_FOR' => '198.51.100.7, 10.0.0.9, 10.0.0.3'];

        self::assertSame('198.51.100.7', IpTools::clientIp($server, self::HEADERS, self::PROXIES));
    }

    public function testGarbageInChainFallsBackToNextHeaderOrRemote(): void
    {
        $server = ['REMOTE_ADDR' => '10.0.0.2', 'HTTP_X_FORWARDED_FOR' => '198.51.100.7, unknown'];
        self::assertSame('10.0.0.2', IpTools::clientIp($server, self::HEADERS, self::PROXIES));

        $server['HTTP_X_REAL_IP'] = '198.51.100.9';
        self::assertSame('198.51.100.9', IpTools::clientIp($server, self::HEADERS, self::PROXIES));
    }

    public function testTrustedHeadersWithoutProxiesAreIgnored(): void
    {
        $server = ['REMOTE_ADDR' => '10.0.0.2', 'HTTP_X_FORWARDED_FOR' => '198.51.100.7'];

        self::assertSame('10.0.0.2', IpTools::clientIp($server, self::HEADERS, []));
    }

    public function testIpv4MappedIpv6IsTreatedAsIpv4(): void
    {
        self::assertSame('203.0.113.5', IpTools::normalize('::ffff:203.0.113.5'));
        self::assertSame('203.0.113.5', IpTools::banKey('::ffff:203.0.113.5'));
    }

    public function testIpv6IsBannedByNetwork64(): void
    {
        self::assertSame('2001:db8:1:2::/64', IpTools::banKey('2001:db8:1:2:aaaa:bbbb:cccc:dddd'));
        self::assertSame(IpTools::banKey('2001:db8:1:2::1'), IpTools::banKey('2001:db8:1:2:ffff::9'));
        self::assertNotSame(IpTools::banKey('2001:db8:1:2::1'), IpTools::banKey('2001:db8:1:3::1'));
    }

    public function testInListSupportsExactAddressesAndCidr(): void
    {
        self::assertTrue(IpTools::inList('192.168.5.77', ['10.0.0.0/8', '192.168.5.0/24']));
        self::assertTrue(IpTools::inList('203.0.113.5', ['203.0.113.5']));
        self::assertFalse(IpTools::inList('203.0.113.6', ['203.0.113.5']));
        self::assertTrue(IpTools::inList('2001:db8::1', ['2001:db8::/32']));
        self::assertFalse(IpTools::inList('2001:db9::1', ['2001:db8::/32']));
        self::assertTrue(IpTools::inList('10.20.30.40', ['10.20.30.41/31']));
        self::assertFalse(IpTools::inList('10.20.30.40', ['мусор', '10.0.0.0/99']));
    }

    public function testCidrValidation(): void
    {
        self::assertTrue(IpTools::isValidCidr('10.0.0.0/8'));
        self::assertTrue(IpTools::isValidCidr('2001:db8::/32'));
        self::assertTrue(IpTools::isValidCidr('203.0.113.5'));
        self::assertFalse(IpTools::isValidCidr('10.0.0.0/33'));
        self::assertFalse(IpTools::isValidCidr('10.0.0.0/'));
        self::assertFalse(IpTools::isValidCidr('office'));
    }
}
