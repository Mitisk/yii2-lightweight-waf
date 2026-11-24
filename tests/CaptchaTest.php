<?php

declare(strict_types=1);

namespace Mitisk\Waf\Tests;

final class CaptchaTest extends WafTestCase
{
    private const KEYS = ['recaptchaSiteKey' => 'site-key', 'recaptchaSecret' => 'secret'];

    public function testWithoutKeysBlockedPageHasNoCaptcha(): void
    {
        $response = $this->request('/wp-login.php');

        self::assertStringNotContainsString('data-sitekey', (string) $response?->body);
        self::assertStringContainsString('временно заблокирован', (string) $response?->body);
        self::assertSame('86400', $response?->headers['Retry-After']);
    }

    public function testBlockedVisitorSeesCaptchaForm(): void
    {
        $response = $this->request('/wp-login.php?a="><script>', self::KEYS);

        self::assertSame(403, $response?->status);
        self::assertStringContainsString('data-sitekey="site-key"', $response->body);
        self::assertStringNotContainsString('"><script>', $response->body, 'Адрес в форме экранирован');
    }

    public function testPassedCaptchaUnblocksAndRedirectsHome(): void
    {
        $this->request('/wp-login.php', self::KEYS);

        $response = $this->request('/', self::KEYS, self::IP, [], ['g-recaptcha-response' => 'token']);

        self::assertSame(302, $response?->status);
        self::assertSame('/', $response->headers['Location']);
        $this->assertPassed($this->request('/', self::KEYS));
        self::assertSame('captcha_ok', $this->storage()->events()[0]['action']);
    }

    public function testFailedCaptchaKeepsBlockAndCountsAttempts(): void
    {
        $this->captchaPasses = false;
        $this->request('/wp-login.php', self::KEYS);

        $response = $this->request('/', self::KEYS, self::IP, [], ['g-recaptcha-response' => 'bad']);

        self::assertSame(403, $response?->status);
        self::assertStringContainsString('Осталось попыток: 4', $response->body);
    }

    public function testCaptchaDisappearsAfterTooManyFailuresAndReturnsAfterWindow(): void
    {
        $config = self::KEYS + ['captchaMaxAttempts' => 2, 'captchaWindow' => 600];
        $this->captchaPasses = false;
        $this->request('/wp-login.php', $config);
        $this->request('/', $config, self::IP, [], ['g-recaptcha-response' => 'bad']);
        $this->request('/', $config, self::IP, [], ['g-recaptcha-response' => 'bad']);

        self::assertStringNotContainsString('data-sitekey', (string) $this->request('/', $config)?->body);

        $this->now += 601;
        self::assertStringContainsString('data-sitekey', (string) $this->request('/', $config)?->body);
    }

    public function testPostWithoutTokenIsNotAnAttempt(): void
    {
        $this->request('/wp-login.php', self::KEYS);

        $response = $this->request('/feedback', self::KEYS, self::IP, [], ['name' => 'Аня']);

        self::assertStringContainsString('data-sitekey', (string) $response?->body);
        self::assertStringNotContainsString('Осталось попыток', (string) $response?->body);
    }

    public function testPermanentBanCanBeLiftedByCaptcha(): void
    {
        $config = self::KEYS + ['permanentBlock' => true];
        $this->request('/wp-login.php', $config);

        $this->request('/', $config, self::IP, [], ['g-recaptcha-response' => 'token']);

        $this->assertPassed($this->request('/', $config));
    }
}
