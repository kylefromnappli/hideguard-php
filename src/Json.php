<?php

declare(strict_types=1);

namespace HideGuard;

/**
 * JSON written the way `JSON.stringify` writes it, and the list/record distinction JavaScript
 * makes and PHP arrays do not.
 *
 * The request bodies are held byte for byte to the ones `@hideguard/node` sends
 * (`tests/fixtures/requests.json`), so: slashes and non-ASCII unescaped, U+2028/U+2029 left raw,
 * a non-finite float written as `null`, invalid UTF-8 replaced rather than failing the call.
 *
 * @internal
 */
final class Json
{
    const FLAGS = JSON_UNESCAPED_SLASHES
        | JSON_UNESCAPED_UNICODE
        | JSON_UNESCAPED_LINE_TERMINATORS
        | JSON_INVALID_UTF8_SUBSTITUTE;

    private function __construct()
    {
    }

    /** @param mixed $value */
    public static function encode($value): string
    {
        $text = json_encode(self::prepare($value), self::FLAGS);
        if ($text === false) {
            throw new HideGuardError(
                HideGuardError::INVALID_ARGUMENT,
                'the request could not be encoded as JSON: ' . json_last_error_msg()
            );
        }
        return $text;
    }

    /**
     * A reply body as decoded JSON, or null when it is not JSON (an HTML error page from a
     * proxy). JSON objects become associative arrays.
     *
     * @return mixed
     */
    public static function decode(string $text)
    {
        if ($text === '') {
            return null;
        }
        $value = json_decode($text, true);
        return json_last_error() === JSON_ERROR_NONE ? $value : null;
    }

    /** Whether an array's keys are 0, 1, 2… in order — what JavaScript would call an array. */
    public static function isList(array $value): bool
    {
        $expected = 0;
        foreach ($value as $key => $unused) {
            if ($key !== $expected) {
                return false;
            }
            $expected++;
        }
        return true;
    }

    /**
     * The record behind a value — an associative array or an object's properties — or null for
     * anything JavaScript would not call an object: a scalar, null, or a non-empty list. An empty
     * array is a record, being what `json_decode('{}', true)` gives.
     *
     * @param mixed $value
     * @return array<string|int, mixed>|null
     */
    public static function record($value)
    {
        if ($value instanceof \stdClass) {
            return get_object_vars($value);
        }
        if (is_array($value) && ($value === [] || !self::isList($value))) {
            return $value;
        }
        return null;
    }

    /** A float spelt the way JavaScript's `String(number)` spells it, near enough for digits. */
    public static function number(float $value): string
    {
        $text = json_encode($value);
        if ($text === false) {
            return 'null';
        }
        return str_replace(['.0e', 'e+', 'E'], ['e', 'e+', 'e'], $text);
    }

    /**
     * @param mixed $value
     * @return mixed
     */
    private static function prepare($value)
    {
        if (is_float($value) && !is_finite($value)) {
            return null;
        }
        if (is_array($value)) {
            $prepared = [];
            foreach ($value as $key => $item) {
                $prepared[$key] = self::prepare($item);
            }
            return $prepared;
        }
        if ($value instanceof \stdClass) {
            $prepared = new \stdClass();
            foreach (get_object_vars($value) as $key => $item) {
                $prepared->{$key} = self::prepare($item);
            }
            return $prepared;
        }
        return $value;
    }
}
