<?php

declare(strict_types=1);

namespace Mitisk\Waf;

/**
 * Проверка «это настоящий поисковый робот»: User-Agent называет робота, обратная DNS-запись
 * адреса лежит в домене поисковика, а прямая запись этого имени возвращает тот же адрес.
 *
 * Нужна, чтобы ссылка на /wp-login.php, которую кто-то разместил в интернете, не закрыла сайт
 * для Googlebot. DNS-запросы идут только в момент срабатывания шаблона, не на каждый запрос.
 */
final class BotVerifier
{
    /** Подстрока User-Agent (в нижнем регистре) → допустимые окончания имени хоста. */
    private const BOTS = [
        'googlebot' => ['.googlebot.com', '.google.com'],
        'yandex' => ['.yandex.ru', '.yandex.net', '.yandex.com'],
        'bingbot' => ['.search.msn.com'],
    ];

    /** @var callable(string): ?string */
    private $reverse;

    /** @var callable(string): string[] */
    private $forward;

    /**
     * @param (callable(string): ?string)|null $reverse адрес → имя хоста (null — записи нет)
     * @param (callable(string): string[])|null $forward имя хоста → адреса
     */
    public function __construct(?callable $reverse = null, ?callable $forward = null)
    {
        $this->reverse = $reverse ?? static function (string $ip): ?string {
            $host = @gethostbyaddr($ip);

            return is_string($host) && $host !== $ip ? $host : null;
        };
        $this->forward = $forward ?? static function (string $host): array {
            $ips = @gethostbynamel($host) ?: [];
            foreach (@dns_get_record($host, DNS_AAAA) ?: [] as $record) {
                if (!empty($record['ipv6'])) {
                    $ips[] = $record['ipv6'];
                }
            }

            return $ips;
        };
    }

    public function isVerified(string $ip, string $userAgent): bool
    {
        $userAgent = strtolower($userAgent);
        $suffixes = null;
        foreach (self::BOTS as $needle => $domains) {
            if (str_contains($userAgent, $needle)) {
                $suffixes = $domains;
                break;
            }
        }
        if ($suffixes === null) {
            return false;
        }

        $host = ($this->reverse)($ip);
        if ($host === null) {
            return false;
        }
        $host = strtolower(rtrim($host, '.'));
        $inDomain = false;
        foreach ($suffixes as $suffix) {
            if (str_ends_with($host, $suffix)) {
                $inDomain = true;
                break;
            }
        }
        if (!$inDomain) {
            return false;
        }

        $normalized = IpTools::normalize($ip);
        foreach (($this->forward)($host) as $resolved) {
            if (is_string($resolved) && IpTools::normalize($resolved) === $normalized) {
                return true;
            }
        }

        return false;
    }
}
