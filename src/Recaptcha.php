<?php

declare(strict_types=1);

namespace Mitisk\Waf;

/**
 * Проверка токена Google reCAPTCHA v2.
 */
final class Recaptcha
{
    private const URL = 'https://www.google.com/recaptcha/api/siteverify';
    private const TIMEOUT = 5;

    public static function verify(string $secret, string $token, string $ip): bool
    {
        if ($secret === '') {
            return false;
        }
        $body = self::post(['secret' => $secret, 'response' => $token, 'remoteip' => $ip]);
        if ($body === null) {
            return false;
        }
        $json = json_decode($body, true);

        return is_array($json) && !empty($json['success']);
    }

    /**
     * POST-запрос: cURL, если он есть, иначе stream context (хостинги без cURL).
     * Второй способ не пробуется после сбоя первого — иначе заблокированный ждёт два таймаута.
     *
     * @param array<string, string> $data
     */
    private static function post(array $data): ?string
    {
        $payload = http_build_query($data);

        if (function_exists('curl_init')) {
            $ch = curl_init(self::URL);
            if ($ch === false) {
                return null;
            }
            curl_setopt_array($ch, [
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => $payload,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_CONNECTTIMEOUT => self::TIMEOUT,
                CURLOPT_TIMEOUT => self::TIMEOUT,
                CURLOPT_HTTPHEADER => ['Content-Type: application/x-www-form-urlencoded'],
            ]);
            $result = curl_exec($ch);
            $code = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);

            return is_string($result) && $code >= 200 && $code < 300 ? $result : null;
        }

        $context = stream_context_create([
            'http' => [
                'header' => "Content-Type: application/x-www-form-urlencoded\r\n",
                'method' => 'POST',
                'content' => $payload,
                'timeout' => self::TIMEOUT,
            ],
        ]);
        $result = @file_get_contents(self::URL, false, $context);

        return is_string($result) ? $result : null;
    }
}
