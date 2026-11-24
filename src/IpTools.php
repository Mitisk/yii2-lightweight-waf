<?php

declare(strict_types=1);

namespace Mitisk\Waf;

/**
 * Работа с IP-адресами: адрес клиента за прокси, списки IP/CIDR, ключ блокировки.
 */
final class IpTools
{
    /**
     * Адрес клиента.
     *
     * По умолчанию — только REMOTE_ADDR. Заголовки читаются, только если REMOTE_ADDR входит
     * в $trustedProxies. Цепочка X-Forwarded-For разбирается справа налево: клиент — первый адрес,
     * который не является доверенным прокси. Всё, что левее, прислал сам клиент и не учитывается
     * (иначе подделкой заголовка можно уйти от блокировки или заблокировать чужой адрес).
     *
     * @param array<string, mixed> $server $_SERVER
     * @param string[] $trustedHeaders
     * @param string[] $trustedProxies IP или CIDR
     */
    public static function clientIp(array $server, array $trustedHeaders, array $trustedProxies): string
    {
        $remote = self::normalize((string) ($server['REMOTE_ADDR'] ?? '')) ?? '127.0.0.1';

        if ($trustedHeaders === []) {
            return $remote;
        }
        if ($trustedProxies === []) {
            self::warnOnce('[LightweightWaf] trustedHeaders задан без trustedProxies — заголовки игнорируются для защиты от IP-спуфинга.');
            return $remote;
        }
        if (!self::inList($remote, $trustedProxies)) {
            return $remote;
        }

        foreach ($trustedHeaders as $header) {
            $key = 'HTTP_' . strtoupper(str_replace('-', '_', (string) $header));
            $value = $server[$key] ?? '';
            if (!is_string($value) || $value === '') {
                continue;
            }
            $chain = array_reverse(array_map('trim', explode(',', $value)));
            foreach ($chain as $candidate) {
                $ip = self::normalize($candidate);
                if ($ip === null) {
                    // Мусор в цепочке: дальше влево доверять нечему
                    break;
                }
                if (!self::inList($ip, $trustedProxies)) {
                    return $ip;
                }
            }
        }

        return $remote;
    }

    /**
     * Канонический вид адреса; IPv4, записанный как IPv6 (::ffff:1.2.3.4), — обычный IPv4.
     * Не адрес — null.
     */
    public static function normalize(string $ip): ?string
    {
        $ip = trim($ip);
        if ($ip === '') {
            return null;
        }
        $bin = @inet_pton($ip);
        if ($bin === false) {
            return null;
        }
        if (strlen($bin) === 16 && str_starts_with($bin, "\0\0\0\0\0\0\0\0\0\0\xff\xff")) {
            $bin = substr($bin, 12);
        }
        $text = inet_ntop($bin);

        return $text === false ? null : $text;
    }

    /**
     * Ключ блокировки: для IPv4 — сам адрес, для IPv6 — сеть /64 (провайдер выдаёт клиенту
     * целую /64, и сканер меняет адреса внутри неё бесплатно).
     */
    public static function banKey(string $ip): string
    {
        $normalized = self::normalize($ip);
        if ($normalized === null) {
            return $ip;
        }
        $bin = inet_pton($normalized);
        if ($bin === false || strlen($bin) !== 16) {
            return $normalized;
        }

        return inet_ntop(substr($bin, 0, 8) . str_repeat("\0", 8)) . '/64';
    }

    /**
     * Входит ли адрес в список IP и CIDR (IPv4 и IPv6).
     *
     * @param string[] $cidrs
     */
    public static function inList(string $ip, array $cidrs): bool
    {
        $normalized = self::normalize($ip);
        $ipBin = $normalized === null ? false : inet_pton($normalized);
        if ($ipBin === false) {
            return false;
        }

        foreach ($cidrs as $cidr) {
            $range = self::parseCidr((string) $cidr);
            if ($range === null || strlen($range[0]) !== strlen($ipBin)) {
                continue;
            }
            [$subnetBin, $mask] = $range;
            $bytes = intdiv($mask, 8);
            $bits = $mask % 8;

            if ($bytes > 0 && substr($ipBin, 0, $bytes) !== substr($subnetBin, 0, $bytes)) {
                continue;
            }
            if ($bits === 0) {
                return true;
            }
            $maskByte = (~((1 << (8 - $bits)) - 1)) & 0xFF;
            if ((ord($ipBin[$bytes]) & $maskByte) === (ord($subnetBin[$bytes]) & $maskByte)) {
                return true;
            }
        }

        return false;
    }

    /** Правильная ли запись IP или CIDR. */
    public static function isValidCidr(string $cidr): bool
    {
        return self::parseCidr($cidr) !== null;
    }

    /**
     * @return array{0: string, 1: int}|null [адрес сети в бинарном виде, длина маски]
     */
    private static function parseCidr(string $cidr): ?array
    {
        $cidr = trim($cidr);
        $mask = null;
        if (str_contains($cidr, '/')) {
            [$cidr, $maskText] = explode('/', $cidr, 2);
            if ($maskText === '' || !ctype_digit($maskText)) {
                return null;
            }
            $mask = (int) $maskText;
        }

        $normalized = self::normalize($cidr);
        $bin = $normalized === null ? false : inet_pton($normalized);
        if ($bin === false) {
            return null;
        }
        $max = strlen($bin) * 8;
        $mask ??= $max;

        return $mask > $max ? null : [$bin, $mask];
    }

    private static function warnOnce(string $message): void
    {
        static $warned = [];
        if (isset($warned[$message])) {
            return;
        }
        $warned[$message] = true;
        @error_log($message);
    }
}
