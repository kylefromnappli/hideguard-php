<?php

declare(strict_types=1);

namespace HideGuard;

/**
 * What a call sends, decided before anything is sent — `@hideguard/node`'s `requests.ts`, ported.
 *
 * Nothing in here touches the network or a clock. Every method either returns the exact
 * request (method, URL, headers, JSON text) or throws a HideGuardError naming the field that
 * made the call unsendable. `tests/fixtures/requests.json` is computed from the TypeScript, and
 * the PHP suite holds every URL, header and body byte here to it.
 *
 * Two rules are load-bearing:
 *
 *  - **A card number never leaves the merchant's process.** Every field the routes refuse a
 *    card number in is checked with `CardNumber::carries` first.
 *  - **Only named fields travel.** The verdict's `payment` block, the forwarded headers and
 *    `cardDetails` are picked field by field, so passing a whole gateway object or a request's
 *    every header (cookie and authorization included) sends only what the route reads.
 *
 * @internal
 */
final class Requests
{
    const DEFAULT_ENDPOINT = 'https://hideguard.io';
    const DEFAULT_TIMEOUT_MS = 2000;
    const MAX_TIMEOUT_MS = 2147483647;

    const PAYMENT_OUTCOMES = ['approved', 'declined', 'blocked', 'abandoned'];

    const CARD_DETAIL_FIELDS = [
        'brand', 'country', 'funding', 'wallet', 'cvcCheck', 'postalCheck',
        'threeDSecure', 'gatewayOutcome', 'gatewayRiskLevel', 'gatewayRiskScore',
    ];

    /** The forwarded headers the verdict route reads, and the camel-case spelling also accepted. */
    const FORWARDED_HEADERS = [
        'accept-language' => 'acceptLanguage',
        'sec-ch-ua' => 'secChUa',
        'sec-fetch-mode' => 'secFetchMode',
    ];

    const PAYMENT_FIELDS = ['card', 'amount', 'currency', 'reference', 'method', 'provider', 'accountRef'];

    const REPORT_FIELDS = ['attemptId', 'reference', 'outcome', 'declineCode', 'card', 'eventId'];

    private function __construct()
    {
    }

    /* ------------------------------------------------------------- configuration */

    /**
     * The collector's base URL, without a trailing slash.
     *
     * `https:` only, except on loopback, because every authenticated call carries the site
     * secret in a header. Credentials, a query or a fragment are refused rather than tidied.
     *
     * @param mixed $raw null for the default
     */
    public static function normalizeEndpoint($raw): string
    {
        if ($raw !== null && !is_string($raw)) {
            throw self::invalid('endpoint', 'endpoint must be a string URL (expected e.g. https://hideguard.io)');
        }
        $value = $raw === null ? self::DEFAULT_ENDPOINT : self::trim($raw);
        $parts = preg_match('/[\x00-\x20\x7f]/', $value) ? false : parse_url($value);
        if ($parts === false || !isset($parts['scheme'], $parts['host']) || $parts['host'] === '') {
            throw self::invalid('endpoint', 'endpoint is not an absolute URL (expected e.g. https://hideguard.io)');
        }
        $scheme = strtolower($parts['scheme']);
        $host = strtolower($parts['host']);
        if ($scheme !== 'https' && !($scheme === 'http' && self::isLoopbackHost($host))) {
            throw self::invalid('endpoint', 'endpoint must be https:// (plain http:// is allowed only for localhost)');
        }
        if (isset($parts['user']) || isset($parts['pass'])) {
            throw self::invalid('endpoint', 'endpoint must not carry credentials; the secret goes in secretKey');
        }
        if (isset($parts['query']) || isset($parts['fragment']) || strpbrk($value, '?#') !== false) {
            throw self::invalid('endpoint', 'endpoint must not carry a query string or fragment');
        }
        $port = isset($parts['port']) ? (int) $parts['port'] : null;
        $defaultPort = $scheme === 'https' ? 443 : 80;
        $origin = $scheme . '://' . $host . ($port !== null && $port !== $defaultPort ? ':' . $port : '');
        $path = isset($parts['path']) ? rtrim($parts['path'], '/') : '';
        return $origin . $path;
    }

    /**
     * The site secret, or why it cannot be one. A public key (`pk_…`) is refused here rather
     * than by a 401 later.
     *
     * @param mixed $raw
     */
    public static function normalizeSecret($raw): string
    {
        $value = is_string($raw) ? self::trim($raw) : '';
        if ($value === '') {
            throw self::invalid('secretKey', 'secretKey is missing: set it to the site secret (sk_…) from Dashboard → API keys');
        }
        if (preg_match('/^pk_/i', $value)) {
            throw self::invalid('secretKey', 'secretKey is a public key (pk_…); the server needs the site secret (sk_…)');
        }
        if (preg_match('/[\r\n]/', $value)) {
            throw self::invalid('secretKey', 'secretKey contains a line break');
        }
        return $value;
    }

    /**
     * @param mixed $raw null for the default
     */
    public static function normalizeTimeout($raw, string $field = 'timeoutMs'): int
    {
        if ($raw === null) {
            return self::DEFAULT_TIMEOUT_MS;
        }
        if ((!is_int($raw) && !is_float($raw)) || !is_finite((float) $raw) || $raw <= 0 || $raw > self::MAX_TIMEOUT_MS) {
            throw self::invalid($field, $field . ' must be a positive number of milliseconds');
        }
        return (int) ceil($raw);
    }

    /* --------------------------------------------------------------------- plans */

    /**
     * @param array<string, mixed> $input
     * @return array{method: string, url: string, headers: array<string, string>, body: string|null}
     */
    public static function planVerdict(string $base, string $secret, string $userAgent, $input): array
    {
        return [
            'method' => 'POST',
            'url' => $base . '/api/v1/verdict',
            'headers' => self::jsonHeaders($secret, $userAgent, true),
            'body' => Json::encode((object) self::verdictBody($input)),
        ];
    }

    /**
     * @param array<string, mixed> $input
     * @return array{method: string, url: string, headers: array<string, string>, body: string|null}
     */
    public static function planReportPayment(string $base, string $secret, string $userAgent, $input): array
    {
        return [
            'method' => 'POST',
            'url' => $base . '/api/v1/payments',
            'headers' => self::jsonHeaders($secret, $userAgent, true),
            'body' => Json::encode((object) self::reportBody($input)),
        ];
    }

    /**
     * `GET /api/v1/site`. The secret is a header and the URL carries nothing at all.
     *
     * @return array{method: string, url: string, headers: array<string, string>, body: string|null}
     */
    public static function planSite(string $base, string $secret, string $userAgent): array
    {
        return [
            'method' => 'GET',
            'url' => $base . '/api/v1/site',
            'headers' => self::jsonHeaders($secret, $userAgent, false),
            'body' => null,
        ];
    }

    /**
     * `GET /api/v1/signing-key?siteKey=…`: a public route, so **no** `x-api-key`. A value equal
     * to the secret is refused, because that is the one mistake that would put it in a URL.
     *
     * @return array{method: string, url: string, headers: array<string, string>, body: string|null}
     */
    public static function planSigningKeys(string $base, string $secret, string $userAgent, string $siteKey): array
    {
        $key = self::trim($siteKey);
        if ($key === '') {
            throw self::invalid('siteKey', 'siteKey is empty');
        }
        if ($key === $secret || preg_match('/^sk_/i', $key)) {
            throw self::invalid('siteKey', 'siteKey must be the public key (pk_…), never the site secret: it goes in a URL');
        }
        return [
            'method' => 'GET',
            'url' => $base . '/api/v1/signing-key?siteKey=' . self::encodeUriComponent($key),
            'headers' => self::jsonHeaders(null, $userAgent, false),
            'body' => null,
        ];
    }

    /* --------------------------------------------------------------------- bodies */

    /**
     * The body of `POST /api/v1/verdict`.
     *
     * @param mixed $input
     * @return array<string, mixed>
     */
    public static function verdictBody($input): array
    {
        $input = Json::record($input);
        if ($input === null) {
            throw self::invalid(null, 'verdict() takes an array');
        }
        $payment = null;
        if (array_key_exists('payment', $input) && $input['payment'] !== null) {
            $payment = Json::record($input['payment']);
            if ($payment === null) {
                throw self::invalid('payment', 'payment must be an array');
            }
            $field = self::cardNumberField([
                'payment.card' => self::get($payment, 'card'),
                'payment.reference' => self::get($payment, 'reference'),
                'payment.accountRef' => self::get($payment, 'accountRef'),
                'payment.provider' => self::get($payment, 'provider'),
            ]);
            if ($field !== null) {
                throw self::cardRefusal($field);
            }
        }

        $headers = array_key_exists('headers', $input) ? $input['headers'] : null;
        if ($headers !== null && !is_array($headers) && !is_object($headers)) {
            throw self::invalid('headers', 'headers must be an array of header values or a request/header-bag object');
        }
        $userAgent = self::get($input, 'userAgent');
        if ($userAgent === null && $headers !== null) {
            $userAgent = self::readHeader($headers, 'user-agent');
        }

        $body = [];
        foreach (['requestId', 'visitorId', 'ip'] as $key) {
            if (array_key_exists($key, $input)) {
                $body[$key] = $input[$key];
            }
        }
        if ($userAgent !== null) {
            $body['userAgent'] = $userAgent;
        }
        if ($headers !== null) {
            $body['headers'] = (object) self::pickForwardedHeaders($headers);
        }
        if ($payment !== null) {
            $block = [];
            foreach (self::PAYMENT_FIELDS as $key) {
                if (array_key_exists($key, $payment)) {
                    $block[$key] = $payment[$key];
                }
            }
            $body['payment'] = (object) $block;
        }
        return $body;
    }

    /**
     * The body of `POST /api/v1/payments`. Fields are passed through as given — absent is
     * omitted, anything else (null included) travels, so the route's own rules keep their force.
     *
     * @param mixed $input
     * @return array<string, mixed>
     */
    public static function reportBody($input): array
    {
        $source = Json::record($input);
        if ($source === null) {
            throw self::invalid(null, 'reportPayment() takes an array');
        }
        $field = self::cardNumberField([
            'card' => self::get($source, 'card'),
            'reference' => self::get($source, 'reference'),
            'eventId' => self::get($source, 'eventId'),
            'declineCode' => self::get($source, 'declineCode'),
            'cardDetails' => self::get($source, 'cardDetails'),
        ]);
        if ($field !== null) {
            throw self::cardRefusal($field);
        }
        if (!in_array(self::get($source, 'outcome'), self::PAYMENT_OUTCOMES, true)) {
            throw self::invalid('outcome', 'outcome must be "approved", "declined", "blocked" or "abandoned"');
        }
        $reference = self::get($source, 'reference');
        if (!array_key_exists('attemptId', $source) && (!is_string($reference) || self::trim($reference) === '')) {
            throw self::invalid(
                'attemptId',
                'reportPayment() needs attemptId (from verdict()["payment"]) or reference (the gateway\'s session id)'
            );
        }

        $body = [];
        foreach (self::REPORT_FIELDS as $key) {
            if (array_key_exists($key, $source)) {
                $body[$key] = $source[$key];
            }
        }
        // Only the known keys of `cardDetails` travel: an array built from a gateway reply may
        // hold anything, and the server is not where an unknown field should first be noticed.
        if (array_key_exists('cardDetails', $source)) {
            $details = $source['cardDetails'];
            $record = Json::record($details);
            if ($record !== null) {
                $picked = [];
                foreach (self::CARD_DETAIL_FIELDS as $key) {
                    if (array_key_exists($key, $record)) {
                        $picked[$key] = $record[$key];
                    }
                }
                $body['cardDetails'] = (object) $picked;
            } elseif ($details === null) {
                $body['cardDetails'] = null;
            }
        }
        return $body;
    }

    /* -------------------------------------------------------------------- headers */

    /**
     * The three headers the verdict route judges, and nothing else from `$source`. Absent is
     * left out rather than sent empty; the block itself is sent whenever headers were passed.
     *
     * @param array<string, mixed>|object $source
     * @return array<string, string>
     */
    public static function pickForwardedHeaders($source): array
    {
        $picked = [];
        foreach (self::FORWARDED_HEADERS as $name => $camel) {
            $value = self::readHeader($source, $name);
            if ($value === null) {
                $value = self::readHeader($source, $camel);
            }
            if ($value !== null && self::trim($value) !== '') {
                $picked[$name] = $value;
            }
        }
        return $picked;
    }

    /**
     * One header from what a PHP application has to hand:
     *
     *  - a PSR-7 message (`getHeaderLine`);
     *  - a Symfony/Laravel `HeaderBag` or anything with `get($name)`;
     *  - an array of name => value or name => [values], any capitalisation — `getallheaders()`,
     *    `$request->headers->all()`;
     *  - `$_SERVER`, whose `HTTP_ACCEPT_LANGUAGE` spelling is read as a last resort.
     *
     * @param array<string, mixed>|object $source
     */
    public static function readHeader($source, string $name)
    {
        if (is_object($source) && !$source instanceof \stdClass) {
            if (method_exists($source, 'getHeaderLine')) {
                $line = $source->getHeaderLine($name);
                return is_string($line) && $line !== '' ? $line : null;
            }
            if (method_exists($source, 'get')) {
                return self::headerText($source->get($name));
            }
            return null;
        }
        $record = is_object($source) ? get_object_vars($source) : $source;
        if (array_key_exists($name, $record)) {
            $exact = self::headerText($record[$name]);
            if ($exact !== null) {
                return $exact;
            }
        }
        // A plain array may have kept the client's own capitalisation (`Accept-Language`). The
        // name is not lowered: `acceptLanguage` matches only as written, as in the Node package.
        foreach ($record as $key => $value) {
            if (is_string($key) && strtolower($key) === $name) {
                return self::headerText($value);
            }
        }
        $server = 'HTTP_' . strtoupper(str_replace('-', '_', $name));
        if (array_key_exists($server, $record)) {
            return self::headerText($record[$server]);
        }
        return null;
    }

    /* -------------------------------------------------------------------- helpers */

    /** JavaScript's `String.prototype.trim`: Unicode whitespace and the BOM, not only ASCII. */
    public static function trim(string $value): string
    {
        $trimmed = preg_replace('/^[\s\x{FEFF}\x{00A0}]+|[\s\x{FEFF}\x{00A0}]+$/u', '', $value);
        return $trimmed === null ? trim($value) : $trimmed;
    }

    /** JavaScript's `encodeURIComponent`: rawurlencode, leaving `!*'()` as they are. */
    public static function encodeUriComponent(string $value): string
    {
        return strtr(rawurlencode($value), ['%21' => '!', '%2A' => '*', '%27' => "'", '%28' => '(', '%29' => ')']);
    }

    /**
     * @param array<string, mixed> $fields
     */
    private static function cardNumberField(array $fields)
    {
        foreach ($fields as $name => $value) {
            if (CardNumber::carries($value)) {
                return $name;
            }
        }
        return null;
    }

    private static function cardRefusal(string $field): HideGuardError
    {
        return new HideGuardError(
            HideGuardError::CARD_NUMBER,
            $field . " looks like a card number. Send the processor's card fingerprint (Stripe's card.fingerprint), the gateway's session/order id or event id — never the card. Nothing was sent.",
            ['field' => $field]
        );
    }

    private static function invalid($field, string $message): HideGuardError
    {
        return new HideGuardError(HideGuardError::INVALID_ARGUMENT, $message, ['field' => $field]);
    }

    /**
     * @param mixed $value
     */
    private static function headerText($value)
    {
        if (is_string($value)) {
            return $value;
        }
        if (is_array($value)) {
            $parts = array_values(array_filter($value, 'is_string'));
            return $parts ? implode(', ', $parts) : null;
        }
        return null;
    }

    /**
     * @param array<string|int, mixed> $record
     * @return mixed
     */
    private static function get(array $record, string $key)
    {
        return array_key_exists($key, $record) ? $record[$key] : null;
    }

    /**
     * @return array<string, string>
     */
    private static function jsonHeaders($secret, string $userAgent, bool $withBody): array
    {
        $headers = ['accept' => 'application/json', 'user-agent' => $userAgent];
        if ($withBody) {
            $headers['content-type'] = 'application/json';
        }
        if ($secret !== null) {
            $headers['x-api-key'] = $secret;
        }
        return $headers;
    }

    private static function isLoopbackHost(string $host): bool
    {
        return in_array($host, ['localhost', '127.0.0.1', '[::1]', '::1'], true);
    }
}
