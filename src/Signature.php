<?php

declare(strict_types=1);

namespace HideGuard;

/**
 * The three signature checks, ported from `src/lib/collect/response-signature.ts` and held to it
 * by `tests/fixtures/signatures.json`, which the TypeScript computes and signs.
 *
 * Protocol v2: Ed25519 over a canonical field list, not over the reply's bytes (the page
 * re-serialises the reply). One `key=value` per line, no trailing newline, under a first line
 * that names the kind of message, so a collect reply, a public verdict and a behaviour
 * acknowledgement can never verify as one another although they share a key.
 *
 * Every check answers false rather than throwing: a malformed claim is a refusal, not a 500 in
 * the customer's checkout. Every pattern is anchored with `\z`, not `$`: PCRE's `$` also matches
 * before a final newline, which JavaScript's does not, and `"<signature>\n"` must be refused.
 *
 * @internal
 */
final class Signature
{
    const PROTOCOL = 2;
    const DEFAULT_TOLERANCE_SECONDS = 300;
    const DEFAULT_CLOCK_SKEW_SECONDS = 30;
    const MAX_SIGNED_REASONS = 64;
    /** Number.MAX_SAFE_INTEGER. */
    const MAX_SAFE_INTEGER = 9007199254740991;

    const COLLECT_LABEL = 'hideguard-collect-ed25519-v2';
    const PUBLIC_VERDICT_LABEL = 'hideguard-verdict-ed25519-v2';
    const BEHAVIOR_ACK_LABEL = 'hideguard-behavior-ack-ed25519-v2';

    const TOKEN_PATTERN = '/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\z/';
    const SIGNATURE_PATTERN = '/^v=2,alg=ed25519,kid=([A-Za-z0-9][A-Za-z0-9._:-]{0,127}),t=([1-9][0-9]{0,11}),sig=([A-Za-z0-9_-]{86})\z/';

    const ENVIRONMENTS = ['production', 'staging', 'development'];
    const VERDICTS = ['allow', 'block', 'challenge'];

    private function __construct()
    {
    }

    /**
     * @param mixed $reply
     * @param array<string, mixed> $options
     */
    public static function verifyReply($reply, array $options, string $label): bool
    {
        try {
            $reply = Json::record($reply);
            if ($reply === null) {
                return false;
            }
            $parsed = self::parseSignature($reply, $options);
            if ($parsed === null) {
                return false;
            }
            list($kid, $timestamp, $signature, $publicKey) = $parsed;

            $environment = self::environmentOf($reply);
            if ($environment === null || !is_array($reasons = self::value($reply, 'reasons')) || !Json::isList($reasons)) {
                return false;
            }
            $codes = [];
            foreach ($reasons as $reason) {
                $reason = Json::record($reason);
                if ($reason === null || !self::isToken(self::value($reason, 'code'))) {
                    return false;
                }
                $codes[] = $reason['code'];
            }
            $score = self::value($reply, 'score');
            if (!is_int($score) && !is_float($score)) {
                return false;
            }
            foreach (['siteId', 'requestId', 'visitorId'] as $field) {
                if (!self::isToken(self::value($reply, $field))) {
                    return false;
                }
            }
            $verdict = self::value($reply, 'verdict');
            if (!is_string($verdict)) {
                return false;
            }
            if ($reply['siteId'] !== self::value($options, 'siteId') || $environment !== self::value($options, 'environment')) {
                return false;
            }

            // What the signer refuses to sign is never a valid message.
            $score = self::safeInteger($score);
            if ($score === null || $score < 0 || !in_array($verdict, self::VERDICTS, true) || count($codes) > self::MAX_SIGNED_REASONS) {
                return false;
            }

            $message = implode("\n", [
                $label,
                'alg=ed25519',
                'kid=' . $kid,
                't=' . $timestamp,
                'site=' . $reply['siteId'],
                'environment=' . $environment,
                'request=' . $reply['requestId'],
                'visitor=' . $reply['visitorId'],
                'verdict=' . $verdict,
                'score=' . $score,
                'reasons=' . ($codes === [] ? '[]' : '["' . implode('","', $codes) . '"]'),
            ]);
            return self::verifyDetached($signature, $message, $publicKey);
        } catch (\Throwable $error) {
            return false;
        }
    }

    /**
     * @param mixed $reply
     * @param array<string, mixed> $options
     */
    public static function verifyAck($reply, array $options): bool
    {
        try {
            $reply = Json::record($reply);
            if ($reply === null) {
                return false;
            }
            $parsed = self::parseSignature($reply, $options);
            if ($parsed === null) {
                return false;
            }
            list($kid, $timestamp, $signature, $publicKey) = $parsed;

            $environment = self::environmentOf($reply);
            $accepted = self::value($reply, 'accepted');
            $lastSeq = self::value($reply, 'lastSeq');
            if ($environment === null || !is_bool($accepted) || (!is_int($lastSeq) && !is_float($lastSeq))) {
                return false;
            }
            foreach (['siteId', 'visitId', 'visitorId', 'documentId', 'batchId'] as $field) {
                if (!self::isToken(self::value($reply, $field))) {
                    return false;
                }
            }
            if ($reply['siteId'] !== self::value($options, 'siteId') || $environment !== self::value($options, 'environment')) {
                return false;
            }
            // The binding: without it the signature proves only that we signed something, not
            // that we signed an answer to the batch the caller sent.
            if ($reply['documentId'] !== self::value($options, 'documentId') || $reply['batchId'] !== self::value($options, 'batchId')) {
                return false;
            }
            $lastSeq = self::safeInteger($lastSeq);
            if ($lastSeq === null || $lastSeq < -1) {
                return false;
            }

            $message = implode("\n", [
                self::BEHAVIOR_ACK_LABEL,
                'alg=ed25519',
                'kid=' . $kid,
                't=' . $timestamp,
                'site=' . $reply['siteId'],
                'environment=' . $environment,
                'visit=' . $reply['visitId'],
                'visitor=' . $reply['visitorId'],
                'document=' . $reply['documentId'],
                'batch=' . $reply['batchId'],
                'lastSeq=' . $lastSeq,
                'accepted=' . ($accepted ? 'true' : 'false'),
            ]);
            return self::verifyDetached($signature, $message, $publicKey);
        } catch (\Throwable $error) {
            return false;
        }
    }

    /**
     * The signature value, checked against the clock and the trusted keys: [kid, timestamp,
     * 64 signature bytes, key], or null.
     *
     * @param array<string|int, mixed> $reply
     * @param array<string, mixed> $options
     * @return array{0: string, 1: int, 2: string, 3: Ed25519PublicKey}|null
     */
    private static function parseSignature(array $reply, array $options)
    {
        $value = self::value($reply, 'signature');
        if (!is_string($value) || !preg_match(self::SIGNATURE_PATTERN, $value, $match)) {
            return null;
        }

        $tolerance = self::safeInteger(array_key_exists('toleranceSeconds', $options) ? $options['toleranceSeconds'] : self::DEFAULT_TOLERANCE_SECONDS);
        $skew = self::safeInteger(array_key_exists('clockSkewSeconds', $options) ? $options['clockSkewSeconds'] : self::DEFAULT_CLOCK_SKEW_SECONDS);
        if ($tolerance === null || $tolerance < 1 || $skew === null || $skew < 0) {
            return null;
        }

        $kid = $match[1];
        $timestamp = (int) $match[2];
        $now = self::nowSeconds(array_key_exists('now', $options) ? $options['now'] : null);
        if ($now === null || $timestamp > $now + $skew || $now - $timestamp > $tolerance) {
            return null;
        }

        $keys = self::value($options, 'publicKeys');
        $publicKey = is_array($keys) && array_key_exists($kid, $keys) ? $keys[$kid] : null;
        if (!$publicKey instanceof Ed25519PublicKey) {
            return null;
        }

        $signature = self::base64UrlDecode($match[3]);
        if ($signature === null || strlen($signature) !== 64 || self::base64UrlEncode($signature) !== $match[3]) {
            return null;
        }
        return [$kid, $timestamp, $signature, $publicKey];
    }

    private static function verifyDetached(string $signature, string $message, Ed25519PublicKey $key): bool
    {
        if (!function_exists('sodium_crypto_sign_verify_detached')) {
            return false;
        }
        return sodium_crypto_sign_verify_detached($signature, $message, $key->bytes());
    }

    /**
     * @param array<string|int, mixed> $reply
     */
    private static function environmentOf(array $reply)
    {
        $environment = self::value($reply, 'environment');
        return is_string($environment) && in_array($environment, self::ENVIRONMENTS, true) ? $environment : null;
    }

    /**
     * Number.isSafeInteger: an int, or a float with no fraction, within ±(2^53 − 1). The int
     * value, or null.
     *
     * @param mixed $value
     */
    private static function safeInteger($value)
    {
        if (is_int($value)) {
            return abs($value) <= self::MAX_SAFE_INTEGER ? $value : null;
        }
        if (is_float($value) && is_finite($value) && floor($value) === $value && abs($value) <= self::MAX_SAFE_INTEGER) {
            return (int) $value;
        }
        return null;
    }

    /**
     * @param mixed $now a DateTimeInterface, a Unix timestamp in seconds, or null for the clock
     */
    private static function nowSeconds($now)
    {
        if ($now === null) {
            return time();
        }
        if ($now instanceof \DateTimeInterface) {
            return $now->getTimestamp();
        }
        if (is_int($now)) {
            return $now;
        }
        return null;
    }

    /**
     * @param mixed $value
     */
    private static function isToken($value): bool
    {
        return is_string($value) && preg_match(self::TOKEN_PATTERN, $value) === 1;
    }

    /**
     * @param array<string|int, mixed> $record
     * @return mixed
     */
    private static function value(array $record, string $key)
    {
        return array_key_exists($key, $record) ? $record[$key] : null;
    }

    private static function base64UrlDecode(string $text)
    {
        $padded = strtr($text, '-_', '+/');
        $padded .= str_repeat('=', (4 - strlen($padded) % 4) % 4);
        $bytes = base64_decode($padded, true);
        return $bytes === false ? null : $bytes;
    }

    private static function base64UrlEncode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
