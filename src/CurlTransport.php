<?php

declare(strict_types=1);

namespace HideGuard;

/**
 * The default transport when ext-curl is loaded.
 *
 * A transport is any callable taking the request array —
 * `['method' => 'POST', 'url' => …, 'headers' => [name => value], 'body' => string|null,
 *   'timeoutMs' => int]` — and returning `['status' => int, 'body' => string]`, or throwing
 * TransportException when no HTTP answer arrived. Pass your own as the `transport` option to
 * route calls through Guzzle, a proxy or a test double.
 *
 * Redirects are **not** followed, on purpose: the request carries the site secret in a header,
 * and a redirect to another host would carry it there. A 3xx surfaces as an `http` error.
 */
final class CurlTransport
{
    /**
     * @param array{method: string, url: string, headers: array<string, string>, body: string|null, timeoutMs: int} $request
     * @return array{status: int, body: string}
     */
    public function __invoke(array $request): array
    {
        $handle = curl_init($request['url']);
        if ($handle === false) {
            throw TransportException::network('curl_init failed');
        }
        $lines = [];
        foreach ($request['headers'] as $name => $value) {
            $lines[] = $name . ': ' . $value;
        }
        // Without this, curl waits up to a second for "100 Continue" before sending a body over 1 KB.
        $lines[] = 'Expect:';
        $timeoutMs = (int) $request['timeoutMs'];
        $options = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => $lines,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT_MS => $timeoutMs,
            CURLOPT_CONNECTTIMEOUT_MS => $timeoutMs,
            // Sub-second timeouts need this on builds that resolve names with signals.
            CURLOPT_NOSIGNAL => true,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS | CURLPROTO_HTTP,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ];
        if ($request['method'] === 'POST') {
            $options[CURLOPT_POST] = true;
            $options[CURLOPT_POSTFIELDS] = (string) $request['body'];
        } elseif ($request['method'] !== 'GET') {
            $options[CURLOPT_CUSTOMREQUEST] = $request['method'];
        }
        curl_setopt_array($handle, $options);

        $text = curl_exec($handle);
        $errno = curl_errno($handle);
        $error = curl_error($handle);
        $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        curl_close($handle);

        if ($text === false || $errno !== 0) {
            if ($errno === CURLE_OPERATION_TIMEDOUT) {
                throw TransportException::timeout($error !== '' ? $error : 'timed out');
            }
            throw TransportException::network($error !== '' ? $error : 'curl error ' . $errno);
        }
        return ['status' => $status, 'body' => (string) $text];
    }
}
