<?php

declare(strict_types=1);

namespace HideGuard;

/**
 * Whether a value carries something that could be a card number — the collector's own guard
 * (`src/lib/collect/card-number.ts`), ported line for line and held to it by
 * `tests/fixtures/card-numbers.json`, which is computed from the TypeScript.
 *
 * It runs before anything is sent, so a PAN wired into the wrong field never leaves the
 * merchant's process: a false refusal costs the integrator a clear error on day one, a false
 * acceptance costs a PCI scope.
 *
 * @internal
 */
final class CardNumber
{
    /** Digits in an integer at which it is treated as a card whatever Luhn says. */
    const CARD_LIKE_INTEGER_DIGITS = 13;

    /** How deep an array or object is read before it is refused outright. */
    const MAX_NESTING = 8;

    private function __construct()
    {
    }

    /** Any run of 13–19 digits passing Luhn, spaces and dashes allowed inside it. */
    public static function contains(string $value): bool
    {
        if (!preg_match_all('/\d[\d -]{11,26}\d/', $value, $matches)) {
            return false;
        }
        foreach ($matches[0] as $match) {
            $digits = str_replace([' ', '-'], '', $match);
            $length = strlen($digits);
            if ($length >= 13 && $length <= 19 && self::passesLuhn($digits)) {
                return true;
            }
        }
        return false;
    }

    /**
     * `contains` for a field of a request, whatever type it is.
     *
     * A string is checked as written and again with every non-alphanumeric character removed
     * (`4242_4242_4242_4242`). An integer of 13 or more digits is refused without a Luhn check;
     * a shorter one, or a float, is spelt out and checked. An array or object has every key and
     * value checked, to a depth of 8, and anything deeper is refused outright.
     *
     * @param mixed $value
     */
    public static function carries($value, int $depth = 0): bool
    {
        if (is_string($value)) {
            if (self::contains($value)) {
                return true;
            }
            $joined = preg_replace('/[^A-Za-z0-9]/', '', $value);
            return $joined !== null && $joined !== $value && self::contains($joined);
        }
        if (is_int($value)) {
            $digits = ltrim((string) $value, '-');
            return strlen($digits) >= self::CARD_LIKE_INTEGER_DIGITS || self::contains($digits);
        }
        if (is_float($value)) {
            if (!is_finite($value)) {
                return false;
            }
            if (floor($value) === $value) {
                // An integral float: JavaScript's Number.isInteger is true here too.
                $digits = sprintf('%.0f', abs($value));
                return strlen($digits) >= self::CARD_LIKE_INTEGER_DIGITS || self::contains($digits);
            }
            return self::contains(Json::number($value));
        }
        if (is_array($value) || is_object($value)) {
            if ($depth >= self::MAX_NESTING) {
                return true;
            }
            $entries = is_object($value) ? get_object_vars($value) : $value;
            $list = is_array($value) && Json::isList($value);
            foreach ($entries as $key => $item) {
                if (!$list && self::carries((string) $key, $depth + 1)) {
                    return true;
                }
                if (self::carries($item, $depth + 1)) {
                    return true;
                }
            }
            return false;
        }
        return false;
    }

    private static function passesLuhn(string $digits): bool
    {
        $sum = 0;
        $length = strlen($digits);
        for ($index = 0; $index < $length; $index++) {
            $digit = (int) $digits[$length - 1 - $index];
            if ($index % 2 === 1) {
                $digit *= 2;
                if ($digit > 9) {
                    $digit -= 9;
                }
            }
            $sum += $digit;
        }
        return $sum % 10 === 0;
    }
}
