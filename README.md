# hideguard/php

Server-side client for [HideGuard](https://hideguard.io): ask for a verdict before you charge,
report how the charge went, and verify signed replies your pages relay. The same API as
[`@hideguard/node`](https://www.npmjs.com/package/@hideguard/node), in PHP's idiom: inputs and
replies are arrays, failures are `HideGuardError`. PHP 7.2.5+, no dependencies.

```sh
composer require hideguard/php
```

Extensions: `ext-json` (required), `ext-curl` (the default transport; without it PHP's HTTP
stream wrapper is used), `ext-sodium` (to verify signed replies; bundled with PHP 7.2+, or
`paragonie/sodium_compat`).

The site **secret** (`sk_…`) belongs on your server only. It is sent in the `x-api-key` header
and nowhere else.

## Quick start

```php
use HideGuard\HideGuard;
use HideGuard\HideGuardError;

$hg = new HideGuard(['secretKey' => getenv('HIDEGUARD_SITE_SECRET')]); // timeoutMs defaults to 2000

// Before creating the charge. Fail open: a HideGuard outage must not stop a checkout.
$verdict = null;
try {
    $verdict = $hg->verdict([
        'requestId' => $requestIdRelayedByThePage,
        'ip' => $clientIp,
        'headers' => getallheaders(),      // only accept-language / sec-ch-ua / sec-fetch-mode / user-agent are sent
        'payment' => ['reference' => $session->id, 'method' => 'stripe', 'amount' => 12.5, 'currency' => 'USD'],
    ]);
} catch (HideGuardError $error) {
    error_log('[hideguard] ' . $error->getErrorCode() . ' ' . $error->getStatus());
}
if ($verdict !== null && $verdict['verdict'] === 'block') { /* refuse, then report outcome 'blocked' */ }

// From the gateway webhook, after your own work is done.
try {
    $hg->reportPayment(['reference' => $session->id, 'outcome' => 'approved']);
} catch (HideGuardError $error) {
    error_log('[hideguard] ' . $error->getErrorCode());
}
```

`headers` takes `getallheaders()`, `$_SERVER`, a PSR-7 request, a Symfony/Laravel `HeaderBag`
(`$request->headers`), or any array of header values.

`reportPayment` takes `attemptId` (from `$verdict['payment']['attemptId']`) or `reference`, an
`outcome` of `approved | declined | blocked | abandoned`, and — on `declined` — the gateway's
`declineCode`, the declined card's processor **fingerprint** as `card`, the webhook's `eventId`,
and `cardDetails`.

**Card numbers are refused locally.** Anything in `payment.card`, `payment.reference`,
`payment.accountRef`, `payment.provider`, `card`, `reference`, `eventId`, `declineCode` or
`cardDetails` that looks like a PAN throws `HideGuardError` with code `card_number`, and nothing
is sent.

## Errors

Every failure is a `HideGuardError` with `getErrorCode()` (`http`, `timeout`, `network`,
`invalid_response`, `card_number`, `invalid_argument`), `getStatus()` (null when there was no HTTP
answer), `getBody()` (the parsed reply) and `getField()`. The client never swallows errors:
failing open is your call, made at the call site as above.

## Verifying a relayed reply

```php
use function HideGuard\publicKeyMap;
use function HideGuard\verifyCollectReply;

// Not per request: PHP has no boot, so keep these in configuration or a cache.
$site = $hg->site();                                    // siteId, key, environment…
$keys = $hg->signingKeys(['siteKey' => $site['key']])['keys'];

// Per request: the collect reply the page relayed, decoded.
$ok = verifyCollectReply(json_decode($relayed, true), [
    'siteId' => $site['siteId'],
    'environment' => $site['environment'],
    'publicKeys' => publicKeyMap($keys),
]);
```

`verifyPublicVerdictReply` and `verifyBehaviorAck` take the same options (`verifyBehaviorAck`
also needs the `documentId` and `batchId` you sent). `now` may be a `DateTimeInterface` or a Unix
timestamp; `toleranceSeconds` defaults to 300 and `clockSkewSeconds` to 30.

## Other calls

- `$hg->site()` — `GET /api/v1/site`: `siteId`, `key`, `name`, `environment`, `allowedOrigins`, `managedBy`.
- `$hg->signingKeys(['siteKey' => …])` — `GET /api/v1/signing-key`: `configured`, `keys`, `protocol`.
- `$hg->trustedKeys()` — `publicKeyMap($hg->signingKeys()['keys'])`.
- `publicKeyMap($keys)` — published keys into the array the verifiers take.

Every method takes a last `['timeoutMs' => …]` argument. Pass `'transport' => callable` to the
constructor to send through Guzzle, a proxy or a test double (see `CurlTransport`).

## Differences from `@hideguard/node`

- No `aborted` error and no `signal` option: PHP has nothing to abort a call from outside.
- Redirects are not followed: the request carries the secret, and a redirect would carry it to
  another host. A 3xx is an `http` error.
- Without ext-curl, the timeout bounds each read rather than the whole call.

Full guide (Vietnamese): `docs/integration/php-sdk.md` in the HideGuard repository.

## Development

`php tests/run.php` (or `composer test`). The fixtures in `tests/fixtures/` are computed from the
TypeScript the Node package ships, so a pass means "behaves exactly as `@hideguard/node`".

## License

MIT. See [LICENSE](LICENSE).
