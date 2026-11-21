<?php

/**
 * The whole suite, with no dependency to install: `php tests/run.php` (or `composer test`).
 *
 * Most of it reads tests/fixtures/*.json, which the HideGuard repository computes from the
 * TypeScript `@hideguard/node` ships (`npm run php-sdk:fixtures`), so what is held here is
 * "behaves exactly as the Node package does", not a second set of expectations written by hand.
 * The rest drives the client through a fake transport, and the two real transports through a
 * `php -S` server started for the run.
 */

declare(strict_types=1);

error_reporting(E_ALL);
ini_set('display_errors', '1');
set_error_handler(function ($severity, $message, $file, $line) {
    if (!(error_reporting() & $severity)) {
        return false; // silenced with @, as the wait for the test server is
    }
    throw new ErrorException($message, 0, $severity, $file, $line);
});

$root = dirname(__DIR__);
spl_autoload_register(function ($class) use ($root) {
    if (strpos($class, 'HideGuard\\') === 0) {
        $file = $root . '/src/' . str_replace('\\', '/', substr($class, strlen('HideGuard\\'))) . '.php';
        if (is_file($file)) {
            require $file;
        }
    }
});
require $root . '/src/functions.php';

use HideGuard\CardNumber;
use HideGuard\CurlTransport;
use HideGuard\Ed25519PublicKey;
use HideGuard\HideGuard;
use HideGuard\HideGuardError;
use HideGuard\Requests;
use HideGuard\StreamTransport;
use HideGuard\TransportException;

use function HideGuard\isHideGuardError;
use function HideGuard\publicKeyMap;
use function HideGuard\verifyBehaviorAck;
use function HideGuard\verifyCollectReply;
use function HideGuard\verifyPublicVerdictReply;

$failures = [];
$passed = 0;

function check(bool $condition, string $what): void
{
    global $failures, $passed;
    if ($condition) {
        $passed++;
    } else {
        $failures[] = $what;
    }
}

function same($expected, $actual, string $what): void
{
    check($expected === $actual, $what . "\n      expected " . var_export($expected, true) . "\n      actual   " . var_export($actual, true));
}

/** Runs $call and returns the HideGuardError it throws, or null. */
function refusalOf(callable $call)
{
    try {
        $call();
    } catch (HideGuardError $error) {
        return $error;
    }
    return null;
}

function fixture(string $name, bool $assoc)
{
    global $root;
    $value = json_decode((string) file_get_contents($root . '/tests/fixtures/' . $name), $assoc);
    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new RuntimeException("fixture {$name} is not JSON");
    }
    return $value;
}

/** Top level of a decoded fixture input as an array, its insides left as decoded. */
function topArray($value): array
{
    return is_object($value) ? get_object_vars($value) : $value;
}

/* ------------------------------------------------------------ requests.json */

foreach ([true, false] as $assoc) {
    $label = $assoc ? 'arrays' : 'objects';
    $requests = fixture('requests.json', true);
    $raw = fixture('requests.json', $assoc);
    $rawVerdict = $assoc ? $raw['verdict'] : $raw->verdict;
    $rawReport = $assoc ? $raw['reportPayment'] : $raw->reportPayment;

    $planCases = [
        ['verdict', $requests['verdict'], $rawVerdict, 'planVerdict'],
        ['reportPayment', $requests['reportPayment'], $rawReport, 'planReportPayment'],
    ];
    foreach ($planCases as $planCase) {
        list($kind, $cases, $rawCases, $method) = $planCase;
        foreach ($cases as $index => $case) {
            $rawCase = $assoc ? $rawCases[$index] : $rawCases[$index];
            $input = $assoc ? $rawCase['input'] : $rawCase->input;
            $input = is_object($input) ? get_object_vars($input) : $input;
            $what = "{$kind} [{$label}]: {$case['name']}";
            $plan = null;
            $error = refusalOf(function () use (&$plan, $method, $requests, $input) {
                $plan = Requests::$method($requests['endpoint'], $requests['secret'], $requests['userAgent'], $input);
            });
            if (isset($case['refusal'])) {
                same($case['refusal'], $error ? ['field' => $error->getField(), 'kind' => $error->getErrorCode()] : null, $what);
                continue;
            }
            if ($error) {
                check(false, "{$what}: refused ({$error->getErrorCode()} {$error->getField()}: {$error->getMessage()})");
                continue;
            }
            $expected = $case['request'];
            same($expected['method'], $plan['method'], "{$what}: method");
            same($expected['url'], $plan['url'], "{$what}: url");
            $expectedHeaders = $expected['headers'];
            $actualHeaders = $plan['headers'];
            ksort($expectedHeaders);
            ksort($actualHeaders);
            same($expectedHeaders, $actualHeaders, "{$what}: headers");
            same($expected['body'], $plan['body'], "{$what}: body, byte for byte");
        }
    }
}

$requests = fixture('requests.json', true);
$site = Requests::planSite($requests['endpoint'], $requests['secret'], $requests['userAgent']);
$expectedSite = $requests['site']['request'];
ksort($expectedSite['headers']);
ksort($site['headers']);
ksort($expectedSite);
ksort($site);
same($expectedSite, $site, 'site: the whole request');

foreach ($requests['signingKeys'] as $case) {
    $what = 'signingKeys(' . json_encode($case['siteKey']) . ')';
    $plan = null;
    $error = refusalOf(function () use (&$plan, $requests, $case) {
        $plan = Requests::planSigningKeys($requests['endpoint'], $requests['secret'], $requests['userAgent'], $case['siteKey']);
    });
    if (isset($case['refusal'])) {
        same($case['refusal'], $error ? ['field' => $error->getField(), 'kind' => $error->getErrorCode()] : null, $what);
        continue;
    }
    ksort($case['request']['headers']);
    ksort($plan['headers']);
    ksort($case['request']);
    ksort($plan);
    same($case['request'], $plan, $what);
}

foreach (['endpoints' => 'normalizeEndpoint', 'secrets' => 'normalizeSecret'] as $key => $method) {
    foreach ($requests[$key] as $case) {
        $what = "{$method}(" . json_encode($case['raw']) . ')';
        $value = null;
        $error = refusalOf(function () use (&$value, $method, $case) {
            $value = Requests::$method($case['raw']);
        });
        if (isset($case['refusal'])) {
            same($case['refusal'], $error ? ['field' => $error->getField(), 'kind' => $error->getErrorCode()] : null, $what);
        } else {
            same($case['value'], $value, $what);
        }
    }
}

/* ---------------------------------------------------------- signatures.json */

$signatures = fixture('signatures.json', true);
$keys = publicKeyMap($signatures['keys']);
check(count($keys) === 1 && reset($keys) instanceof Ed25519PublicKey, 'publicKeyMap builds one Ed25519 key from the fixture PEM');
$verifiers = [
    'collect' => 'HideGuard\\verifyCollectReply',
    'public-verdict' => 'HideGuard\\verifyPublicVerdictReply',
    'behavior-ack' => 'HideGuard\\verifyBehaviorAck',
];
foreach ([true, false] as $assoc) {
    $raw = fixture('signatures.json', $assoc);
    $rawCases = $assoc ? $raw['cases'] : $raw->cases;
    foreach ($signatures['cases'] as $index => $case) {
        $reply = $assoc ? $rawCases[$index]['reply'] : $rawCases[$index]->reply;
        $options = $case['options'];
        $now = $options['now'];
        foreach ([new DateTimeImmutable('@' . $now), $now] as $clock) {
            $options['now'] = $clock;
            $options['publicKeys'] = $keys;
            $actual = call_user_func($verifiers[$case['verifier']], $reply, $options);
            same(
                $case['expected'],
                $actual,
                sprintf('%s [%s, now as %s]: %s', $case['verifier'], $assoc ? 'arrays' : 'objects', is_int($clock) ? 'int' : 'DateTime', $case['name'])
            );
        }
    }
}

// A key that is not the one that signed, under the same kid: nothing verifies.
$other = sodium_crypto_sign_publickey(sodium_crypto_sign_keypair());
$wrongKeys = [array_keys($keys)[0] => Ed25519PublicKey::fromRaw($other)];
$served = $signatures['cases'][0];
check(
    !verifyCollectReply($served['reply'], ['now' => $served['options']['now'], 'publicKeys' => $wrongKeys] + $served['options']),
    'a reply verified against another key under the same kid is refused'
);
check(
    !verifyCollectReply($served['reply'], ['now' => $served['options']['now'], 'publicKeys' => []] + $served['options']),
    'an empty key set verifies nothing'
);
$pemByKid = [array_keys($keys)[0] => $signatures['keys'][0]['publicKey']];
check(
    !verifyCollectReply($served['reply'], ['now' => $served['options']['now'], 'publicKeys' => $pemByKid] + $served['options']),
    'a PEM string where a key belongs is refused, not parsed on the fly'
);

/* -------------------------------------------------------- card-numbers.json */

foreach ([true, false] as $assoc) {
    $raw = fixture('card-numbers.json', $assoc);
    $rawCases = $assoc ? $raw['cases'] : $raw->cases;
    $expectedCases = fixture('card-numbers.json', true)['cases'];
    foreach ($expectedCases as $index => $case) {
        $value = $assoc ? $rawCases[$index]['value'] : $rawCases[$index]->value;
        same($case['expected'], CardNumber::carries($value), sprintf('carriesCardNumber [%s] %s', $assoc ? 'arrays' : 'objects', json_encode($case['value'])));
    }
}
check(!CardNumber::carries(NAN) && !CardNumber::carries(INF), 'a non-finite float carries no card');
check(CardNumber::carries(4242424242424242.0), 'an integral float of sixteen digits is a card');

/* -------------------------------------------------------------- publicKeyMap */

$rsa = "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf\n9Cnzj4p4WGeKLs1Pt8QuKUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==\n-----END PUBLIC KEY-----\n";
$cases = [
    'an RSA key' => [[['alg' => 'ed25519', 'kid' => 'k1', 'publicKey' => $rsa]], 'alg'],
    'not a PEM at all' => [[['alg' => 'ed25519', 'kid' => 'k1', 'publicKey' => 'hello']], 'publicKey'],
    'an Ed25519 key under another alg' => [[['alg' => 'rsa', 'kid' => 'k1', 'publicKey' => $signatures['keys'][0]['publicKey']]], 'alg'],
    'no kid' => [[['alg' => 'ed25519', 'publicKey' => $signatures['keys'][0]['publicKey']]], 'kid'],
];
foreach ($cases as $what => $case) {
    $error = refusalOf(function () use ($case) {
        publicKeyMap($case[0]);
    });
    same($case[1], $error ? $error->getField() : null, "publicKeyMap refuses {$what}");
    check($error !== null && $error->getErrorCode() === HideGuardError::INVALID_ARGUMENT, "publicKeyMap refuses {$what} as invalid_argument");
}

/* -------------------------------------------------- the client, faked transport */

final class FakeTransport
{
    /** @var list<array<string, mixed>> */
    public $requests = [];
    /** @var list<mixed> */
    private $answers;

    public function __construct(array $answers)
    {
        $this->answers = $answers;
    }

    public function __invoke(array $request)
    {
        $this->requests[] = $request;
        $answer = array_shift($this->answers);
        if ($answer instanceof Throwable) {
            throw $answer;
        }
        return $answer;
    }
}

function client(FakeTransport $transport, array $options = []): HideGuard
{
    return new HideGuard($options + ['secretKey' => 'sk_test_client', 'transport' => $transport]);
}

$verdictReply = ['verdict' => 'allow', 'score' => 0, 'reasons' => [], 'source' => 'request', 'visitorId' => null];

$transport = new FakeTransport([['status' => 200, 'body' => json_encode($verdictReply)]]);
$reply = client($transport)->verdict(['ip' => '203.0.113.7', 'headers' => ['Cookie' => 'x', 'Accept-Language' => 'vi']]);
same($verdictReply, $reply, 'verdict() returns the decoded reply');
same('https://hideguard.io/api/v1/verdict', $transport->requests[0]['url'], 'verdict() posts to the default endpoint');
same('sk_test_client', $transport->requests[0]['headers']['x-api-key'], 'the secret travels in x-api-key');
same('hideguard-php/' . HideGuard::VERSION, $transport->requests[0]['headers']['user-agent'], 'the user agent names this package and version');
same(2000, $transport->requests[0]['timeoutMs'], 'the default timeout reaches the transport');
same('{"ip":"203.0.113.7","headers":{"accept-language":"vi"}}', $transport->requests[0]['body'], 'only the forwarded header travels');

$transport = new FakeTransport([['status' => 200, 'body' => '{"ok":true,"declineCode":null,"card":false,"eventId":null,"cardDetails":null,"recorded":false}']]);
client($transport, ['timeoutMs' => 500])->reportPayment(['reference' => 'cs_1', 'outcome' => 'abandoned'], ['timeoutMs' => 750]);
same(750, $transport->requests[0]['timeoutMs'], 'a per-call timeout overrides the client one');

$errorCases = [
    'a 401 with the route\'s own message' => [['status' => 401, 'body' => '{"error":"unknown secret"}'], 'http', 401, ['error' => 'unknown secret'], 'HideGuard answered 401 to POST /api/v1/verdict: unknown secret'],
    'a 502 HTML page' => [['status' => 502, 'body' => '<html>bad gateway</html>'], 'http', 502, '<html>bad gateway</html>', 'HideGuard answered 502 to POST /api/v1/verdict'],
    'a 200 that is not a verdict' => [['status' => 200, 'body' => '{"ok":true}'], 'invalid_response', 200, ['ok' => true], null],
    'a 200 that is not JSON' => [['status' => 200, 'body' => 'hello'], 'invalid_response', 200, 'hello', null],
    'a 200 with an empty body' => [['status' => 200, 'body' => ''], 'invalid_response', 200, null, null],
    'a redirect' => [['status' => 302, 'body' => ''], 'http', 302, null, null],
    'a timeout' => [TransportException::timeout('slow'), 'timeout', null, null, 'HideGuard did not answer POST /api/v1/verdict within 2000 ms'],
    'a network failure' => [TransportException::network('refused'), 'network', null, null, 'HideGuard could not be reached (POST /api/v1/verdict)'],
    'any other exception from a custom transport' => [new LogicException('boom'), 'network', null, null, null],
    'a transport that returns nonsense' => [['status' => '200'], 'network', null, null, null],
];
foreach ($errorCases as $what => $case) {
    $transport = new FakeTransport([$case[0]]);
    $error = refusalOf(function () use ($transport) {
        client($transport)->verdict([]);
    });
    if ($error === null) {
        check(false, "verdict() throws on {$what}");
        continue;
    }
    same($case[1], $error->getErrorCode(), "{$what}: code");
    same($case[2], $error->getStatus(), "{$what}: status");
    same($case[3], $error->getBody(), "{$what}: body");
    if ($case[4] !== null) {
        same($case[4], $error->getMessage(), "{$what}: message");
    }
    check(isHideGuardError($error), "{$what}: isHideGuardError");
}

$transport = new FakeTransport([]);
$error = refusalOf(function () use ($transport) {
    client($transport)->verdict(['payment' => ['card' => '4242 4242 4242 4242']]);
});
same('card_number', $error ? $error->getErrorCode() : null, 'a card number is refused');
same([], $transport->requests, 'and nothing was sent');

$siteReply = ['siteId' => 'site_1', 'key' => 'pk_live_1', 'name' => 'Shop', 'environment' => 'production', 'allowedOrigins' => [], 'managedBy' => 'dashboard'];
$transport = new FakeTransport([
    ['status' => 200, 'body' => json_encode($siteReply)],
    ['status' => 200, 'body' => json_encode(['configured' => true, 'keys' => $signatures['keys'], 'protocol' => 2])],
]);
$trusted = client($transport)->trustedKeys();
same(2, count($transport->requests), 'trustedKeys() without a siteKey asks site() first');
same('https://hideguard.io/api/v1/signing-key?siteKey=pk_live_1', $transport->requests[1]['url'], 'then the signing keys of that site');
check(!isset($transport->requests[1]['headers']['x-api-key']), 'and the signing-key request carries no secret');
check(
    verifyCollectReply($served['reply'], ['publicKeys' => $trusted, 'now' => $served['options']['now']] + $served['options']),
    'keys from trustedKeys() verify a reply the collector signed'
);

$constructionCases = [
    'no secret' => [[], 'secretKey'],
    'getenv() of an unset variable' => [['secretKey' => false], 'secretKey'],
    'a public key as the secret' => [['secretKey' => 'pk_live_1'], 'secretKey'],
    'plain http to another host' => [['secretKey' => 'sk_1', 'endpoint' => 'http://hideguard.io'], 'endpoint'],
    'a timeout of zero' => [['secretKey' => 'sk_1', 'timeoutMs' => 0], 'timeoutMs'],
    'a transport that is not callable' => [['secretKey' => 'sk_1', 'transport' => 'not a function'], 'transport'],
];
foreach ($constructionCases as $what => $case) {
    $error = refusalOf(function () use ($case) {
        new HideGuard($case[0]);
    });
    same($case[1], $error ? $error->getField() : null, "new HideGuard() refuses {$what}");
}
same('http://localhost:3000', (new HideGuard(['secretKey' => 'sk_1', 'endpoint' => 'http://localhost:3000/']))->endpoint(), 'endpoint() is the normalised base');
same(['approved', 'declined', 'blocked', 'abandoned'], HideGuard::PAYMENT_OUTCOMES, 'PAYMENT_OUTCOMES');
same(['stripe', 'paypal', 'bank', 'crypto', 'balance'], HideGuard::PAYMENT_METHODS, 'PAYMENT_METHODS');
same(2, HideGuard::SIGNATURE_PROTOCOL, 'SIGNATURE_PROTOCOL');

/* ------------------------------------------------- the real transports, local */

if (function_exists('proc_open')) {
    $port = 18000 + random_int(0, 999);
    $server = proc_open(
        'exec ' . escapeshellarg(PHP_BINARY) . ' -S ' . escapeshellarg("127.0.0.1:{$port}") . ' ' . escapeshellarg(__DIR__ . '/server.php'),
        [0 => ['pipe', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
        $pipes
    );
    $base = "http://127.0.0.1:{$port}";
    for ($attempt = 0; $attempt < 50; $attempt++) {
        $socket = @fsockopen('127.0.0.1', $port, $errno, $errstr, 0.1);
        if ($socket) {
            fclose($socket);
            break;
        }
        usleep(100000);
    }

    $transports = ['stream' => new StreamTransport()];
    if (function_exists('curl_init')) {
        $transports['curl'] = new CurlTransport();
    }
    foreach ($transports as $name => $real) {
        $echo = $real(['method' => 'POST', 'url' => "{$base}/echo", 'headers' => ['x-api-key' => 'sk_1', 'content-type' => 'application/json'], 'body' => '{"a":"ệ"}', 'timeoutMs' => 2000]);
        $seen = json_decode($echo['body'], true);
        same(200, $echo['status'], "{$name}: status");
        same('POST', $seen['method'], "{$name}: method");
        same('{"a":"ệ"}', $seen['body'], "{$name}: body arrives byte for byte");
        same('sk_1', isset($seen['headers']['x-api-key']) ? $seen['headers']['x-api-key'] : null, "{$name}: headers arrive");

        $get = $real(['method' => 'GET', 'url' => "{$base}/get?siteKey=pk_1", 'headers' => ['accept' => 'application/json'], 'body' => null, 'timeoutMs' => 2000]);
        same('GET', json_decode($get['body'], true)['method'], "{$name}: GET");
        same('', json_decode($get['body'], true)['body'], "{$name}: a GET has no body");

        same(401, $real(['method' => 'GET', 'url' => "{$base}/denied", 'headers' => [], 'body' => null, 'timeoutMs' => 2000])['status'], "{$name}: a 401 is an answer, not a failure");
        same(302, $real(['method' => 'GET', 'url' => "{$base}/redirect", 'headers' => [], 'body' => null, 'timeoutMs' => 2000])['status'], "{$name}: redirects are not followed");

        $started = microtime(true);
        $timedOut = null;
        try {
            $real(['method' => 'GET', 'url' => "{$base}/slow", 'headers' => [], 'body' => null, 'timeoutMs' => 300]);
        } catch (TransportException $error) {
            $timedOut = $error->timedOut();
        }
        same(true, $timedOut, "{$name}: a slow answer is a timeout");
        check(microtime(true) - $started < 1.2, "{$name}: and it gave up near the timeout");

        $refused = null;
        try {
            $real(['method' => 'GET', 'url' => 'http://127.0.0.1:1/', 'headers' => [], 'body' => null, 'timeoutMs' => 1000]);
        } catch (TransportException $error) {
            $refused = $error->timedOut();
        }
        same(false, $refused, "{$name}: a refused connection is a network failure");

        // The whole client over the real transport: the echo server answers 200 with a body that
        // is not a site, which is exactly what invalid_response is for.
        $hg = new HideGuard(['secretKey' => 'sk_live_1', 'endpoint' => $base, 'transport' => $real]);
        $error = refusalOf(function () use ($hg) {
            $hg->site();
        });
        same('invalid_response', $error ? $error->getErrorCode() : null, "{$name}: the client reads a real answer");
        $echoed = $error ? $error->getBody() : null;
        same('/api/v1/site', is_array($echoed) ? $echoed['path'] : null, "{$name}: the client asked the right route");
        same('sk_live_1', is_array($echoed) ? $echoed['headers']['x-api-key'] : null, "{$name}: with the secret in x-api-key");
    }
    proc_terminate($server);
    proc_close($server);
} else {
    echo "skipped: the real transports (proc_open is disabled)\n";
}

/* -------------------------------------------------------------------- report */

foreach ($failures as $failure) {
    echo "FAIL {$failure}\n";
}
printf("%s: %d passed, %d failed (PHP %s, sodium %s, curl %s)\n",
    $failures ? 'FAILED' : 'OK', $passed, count($failures), PHP_VERSION,
    function_exists('sodium_crypto_sign_verify_detached') ? 'yes' : 'no',
    function_exists('curl_init') ? 'yes' : 'no');
exit($failures ? 1 : 0);
