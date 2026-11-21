<?php

declare(strict_types=1);

namespace HideGuard;

/**
 * `hideguard/php` — the server-side client a merchant's PHP backend installs instead of
 * hand-writing calls to the collector. The same API as `@hideguard/node`, in PHP's idiom:
 * options and inputs are arrays, replies are decoded JSON arrays, failures are HideGuardError.
 *
 *   $hg = new \HideGuard\HideGuard(['secretKey' => getenv('HIDEGUARD_SITE_SECRET')]);
 *   $verdict = $hg->verdict(['requestId' => $requestId, 'ip' => $ip, 'headers' => getallheaders(),
 *                            'payment' => ['reference' => $sessionId, 'method' => 'stripe']]);
 *   $hg->reportPayment(['reference' => $sessionId, 'outcome' => 'approved']);
 *
 * It never swallows an error: wrap the calls in try/catch where the checkout must go on without
 * HideGuard (README, "fail open").
 */
final class HideGuard
{
    /** This package's version. Requests carry it as `user-agent: hideguard-php/<version>`. */
    const VERSION = '0.2.1';

    /** Every payment outcome the collector accepts, in its own order. */
    const PAYMENT_OUTCOMES = Requests::PAYMENT_OUTCOMES;

    /** Every checkout method the collector keeps, in its own order. Anything else is stored as null. */
    const PAYMENT_METHODS = ['stripe', 'paypal', 'bank', 'crypto', 'balance'];

    /** The fields `cardDetails` may carry; anything else in the array is never sent. */
    const CARD_DETAIL_FIELDS = Requests::CARD_DETAIL_FIELDS;

    /** The signature protocol the verifiers speak. */
    const SIGNATURE_PROTOCOL = Signature::PROTOCOL;

    /** How old a reply the verifiers accept by default, in seconds. */
    const DEFAULT_TOLERANCE_SECONDS = Signature::DEFAULT_TOLERANCE_SECONDS;

    /** How far ahead of your clock a reply's timestamp may be by default, in seconds. */
    const DEFAULT_CLOCK_SKEW_SECONDS = Signature::DEFAULT_CLOCK_SKEW_SECONDS;

    const DEFAULT_ENDPOINT = Requests::DEFAULT_ENDPOINT;
    const DEFAULT_TIMEOUT_MS = Requests::DEFAULT_TIMEOUT_MS;

    /** @var string */
    private $secret;

    /** @var string */
    private $endpoint;

    /** @var int */
    private $timeoutMs;

    /** @var callable */
    private $transport;

    /** @var string */
    private $userAgent;

    /**
     * @param array{secretKey: string|false|null, endpoint?: string, timeoutMs?: int|float, transport?: callable} $options
     *
     *  - `secretKey`: the site secret (`sk_…`) from Dashboard → API keys. Server-side only; sent in
     *    the `x-api-key` header and nowhere else. Accepts `getenv('X')` directly: a missing value
     *    throws `invalid_argument` here, at construction, rather than a 401 at checkout.
     *  - `endpoint`: the collector's base URL. Default `https://hideguard.io`; `http:` only for localhost.
     *  - `timeoutMs`: per-request timeout in milliseconds. Default 2000.
     *  - `transport`: a callable to send requests with instead of curl (see CurlTransport).
     *
     * @throws HideGuardError invalid_argument
     */
    public function __construct(array $options)
    {
        $this->secret = Requests::normalizeSecret(array_key_exists('secretKey', $options) ? $options['secretKey'] : null);
        $this->endpoint = Requests::normalizeEndpoint(array_key_exists('endpoint', $options) ? $options['endpoint'] : null);
        $this->timeoutMs = Requests::normalizeTimeout(array_key_exists('timeoutMs', $options) ? $options['timeoutMs'] : null);
        $transport = array_key_exists('transport', $options) ? $options['transport'] : null;
        if ($transport === null) {
            $transport = function_exists('curl_init') ? new CurlTransport() : new StreamTransport();
        }
        if (!is_callable($transport)) {
            throw new HideGuardError(HideGuardError::INVALID_ARGUMENT, 'transport must be callable', ['field' => 'transport']);
        }
        $this->transport = $transport;
        $this->userAgent = 'hideguard-php/' . self::VERSION;
    }

    /** The collector base URL this client talks to. */
    public function endpoint(): string
    {
        return $this->endpoint;
    }

    /**
     * Ask before acting: `POST /api/v1/verdict`. With `payment`, the attempt is recorded and
     * judged for card testing, and `payment.attemptId` comes back for reportPayment().
     *
     * @param array{
     *   requestId?: string|null, visitorId?: string|null, ip?: string|null, userAgent?: string|null,
     *   headers?: array<string, string|string[]>|object|null,
     *   payment?: array{card?: string|null, amount?: int|float|null, currency?: string|null, reference?: string|null,
     *                   method?: string|null, provider?: string|null, accountRef?: string|null}|null
     * } $input
     * @param array{timeoutMs?: int|float} $options
     * @return array{verdict: string, score: int, reasons: list<array{category: string, code: string, detail: string|null, severity: string, weight: int}>,
     *               source: string, visitorId: string|null,
     *               payment?: array{attemptId: string, measured: bool, method: string|null, reference: string|null, provider?: string|null, account?: bool}}
     * @throws HideGuardError
     */
    public function verdict(array $input, array $options = []): array
    {
        $plan = Requests::planVerdict($this->endpoint, $this->secret, $this->userAgent, $input);
        return $this->send($plan, $options, function (array $body) {
            return is_string(self::field($body, 'verdict'))
                && self::isNumber(self::field($body, 'score'))
                && is_array(self::field($body, 'reasons')) && Json::isList($body['reasons']);
        });
    }

    /**
     * How the charge went: `POST /api/v1/payments`. Name the attempt by `attemptId` (from the
     * verdict) or by the gateway's `reference`; `attemptId` wins. Call it from the gateway's webhook.
     *
     * @param array{
     *   attemptId?: string, reference?: string, outcome: string, declineCode?: string|null, card?: string|null,
     *   cardDetails?: array<string, mixed>|null, eventId?: string|null
     * } $input
     * @param array{timeoutMs?: int|float} $options
     * @return array{ok: true, declineCode: string|null, card: bool, eventId: string|null, cardDetails: array<string, mixed>|null, recorded: bool}
     * @throws HideGuardError
     */
    public function reportPayment(array $input, array $options = []): array
    {
        $plan = Requests::planReportPayment($this->endpoint, $this->secret, $this->userAgent, $input);
        return $this->send($plan, $options, function (array $body) {
            return self::field($body, 'ok') === true;
        });
    }

    /**
     * Which site this secret belongs to: `GET /api/v1/site`.
     *
     * @param array{timeoutMs?: int|float} $options
     * @return array{siteId: string, key: string, name: string, environment: string, allowedOrigins: list<string>, managedBy: string}
     * @throws HideGuardError
     */
    public function site(array $options = []): array
    {
        $plan = Requests::planSite($this->endpoint, $this->secret, $this->userAgent);
        return $this->send($plan, $options, function (array $body) {
            return is_string(self::field($body, 'siteId')) && is_string(self::field($body, 'key'));
        });
    }

    /**
     * The keys replies for this site are signed with: `GET /api/v1/signing-key?siteKey=…`.
     * Without `siteKey`, the site's public key is learned from site() first (two requests).
     * The secret is never sent to this route.
     *
     * @param array{siteKey?: string, timeoutMs?: int|float} $options
     * @return array{configured: bool, keys: list<array{alg: string, kid: string, publicKey: string}>, protocol: int}
     * @throws HideGuardError
     */
    public function signingKeys(array $options = []): array
    {
        $siteKey = isset($options['siteKey']) ? $options['siteKey'] : null;
        if ($siteKey === null) {
            $siteKey = $this->site($options)['key'];
        }
        if (!is_string($siteKey)) {
            throw new HideGuardError(HideGuardError::INVALID_ARGUMENT, 'siteKey must be a string', ['field' => 'siteKey']);
        }
        $plan = Requests::planSigningKeys($this->endpoint, $this->secret, $this->userAgent, $siteKey);
        return $this->send($plan, $options, function (array $body) {
            return is_bool(self::field($body, 'configured'))
                && is_array(self::field($body, 'keys')) && Json::isList($body['keys']);
        });
    }

    /**
     * `publicKeyMap($hg->signingKeys()['keys'])`. Call once at boot and keep the map.
     *
     * @param array{siteKey?: string, timeoutMs?: int|float} $options
     * @return array<string, Ed25519PublicKey>
     * @throws HideGuardError
     */
    public function trustedKeys(array $options = []): array
    {
        return publicKeyMap($this->signingKeys($options)['keys']);
    }

    /**
     * @param array{method: string, url: string, headers: array<string, string>, body: string|null} $plan
     * @param array<string, mixed> $options
     * @return array<string, mixed>
     */
    private function send(array $plan, array $options, callable $shape): array
    {
        $timeoutMs = Requests::normalizeTimeout(array_key_exists('timeoutMs', $options) ? $options['timeoutMs'] : $this->timeoutMs);
        $route = $plan['method'] . ' ' . self::pathOf($plan['url']);
        try {
            $answer = call_user_func($this->transport, $plan + ['timeoutMs' => $timeoutMs]);
        } catch (TransportException $error) {
            if ($error->timedOut()) {
                throw new HideGuardError(HideGuardError::TIMEOUT, "HideGuard did not answer {$route} within {$timeoutMs} ms", ['previous' => $error]);
            }
            throw new HideGuardError(HideGuardError::NETWORK, "HideGuard could not be reached ({$route})", ['previous' => $error]);
        } catch (HideGuardError $error) {
            throw $error;
        } catch (\Throwable $error) {
            throw new HideGuardError(HideGuardError::NETWORK, "HideGuard could not be reached ({$route})", ['previous' => $error]);
        }
        if (!is_array($answer) || !is_int(self::field($answer, 'status')) || !is_string(self::field($answer, 'body'))) {
            throw new HideGuardError(HideGuardError::NETWORK, "HideGuard could not be reached ({$route}): the transport returned no status and body");
        }

        $status = $answer['status'];
        $text = $answer['body'];
        $parsed = Json::decode($text);
        $body = $parsed !== null ? $parsed : ($text !== '' ? $text : null);
        if ($status < 200 || $status > 299) {
            $reason = is_array($parsed) && is_string(self::field($parsed, 'error')) && $parsed['error'] !== '' ? ': ' . $parsed['error'] : '';
            throw new HideGuardError(HideGuardError::HTTP, "HideGuard answered {$status} to {$route}{$reason}", ['status' => $status, 'body' => $body]);
        }
        $record = Json::record($parsed);
        if ($record === null || !$shape($record)) {
            throw new HideGuardError(
                HideGuardError::INVALID_RESPONSE,
                "HideGuard answered {$status} to {$route} with an unexpected body",
                ['status' => $status, 'body' => $body]
            );
        }
        return $record;
    }

    /** The route, for messages: never the query, which is the one place a key could sit. */
    private static function pathOf(string $url): string
    {
        $path = parse_url($url, PHP_URL_PATH);
        return is_string($path) && $path !== '' ? $path : 'request';
    }

    /**
     * @param array<string|int, mixed> $record
     * @return mixed
     */
    private static function field(array $record, string $key)
    {
        return array_key_exists($key, $record) ? $record[$key] : null;
    }

    /** @param mixed $value */
    private static function isNumber($value): bool
    {
        return is_int($value) || is_float($value);
    }
}
