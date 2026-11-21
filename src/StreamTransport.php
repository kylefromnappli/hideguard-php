<?php

declare(strict_types=1);

namespace HideGuard;

/**
 * The fallback transport when ext-curl is not loaded: PHP's own HTTP stream wrapper.
 *
 * One difference from CurlTransport worth knowing: the stream wrapper's timeout bounds each
 * read, not the whole exchange, so a server trickling bytes can hold a call longer than
 * `timeoutMs`. Install ext-curl where that matters. Redirects are not followed, for the reason
 * CurlTransport gives.
 */
final class StreamTransport
{
    /**
     * @param array{method: string, url: string, headers: array<string, string>, body: string|null, timeoutMs: int} $request
     * @return array{status: int, body: string}
     */
    public function __invoke(array $request): array
    {
        $lines = [];
        foreach ($request['headers'] as $name => $value) {
            $lines[] = $name . ': ' . $value;
        }
        $lines[] = 'Connection: close';
        $http = [
            'method' => $request['method'],
            'header' => implode("\r\n", $lines),
            'timeout' => max(0.001, $request['timeoutMs'] / 1000),
            'ignore_errors' => true,
            'follow_location' => 0,
            'max_redirects' => 1,
        ];
        if ($request['body'] !== null) {
            $http['content'] = $request['body'];
        }
        $context = stream_context_create([
            'http' => $http,
            'ssl' => ['verify_peer' => true, 'verify_peer_name' => true],
        ]);

        $warning = null;
        $started = microtime(true);
        set_error_handler(function ($severity, $message) use (&$warning) {
            $warning = $message;
            return true;
        });
        try {
            $text = file_get_contents($request['url'], false, $context);
            $headers = function_exists('http_get_last_response_headers')
                ? http_get_last_response_headers()
                : (isset($http_response_header) ? $http_response_header : null);
        } finally {
            restore_error_handler();
        }

        $status = null;
        if (is_array($headers)) {
            // The last status line wins: with redirects off there is one, but be exact anyway.
            foreach ($headers as $line) {
                if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $match)) {
                    $status = (int) $match[1];
                }
            }
        }
        if ($text === false || $status === null) {
            $message = $warning !== null ? $warning : 'no answer';
            // The wrapper says only "HTTP request failed!" when a read times out, so the clock
            // is what tells a timeout from a refusal.
            $elapsedMs = (microtime(true) - $started) * 1000;
            if (stripos($message, 'timed out') !== false || $elapsedMs >= $request['timeoutMs'] * 0.95) {
                throw TransportException::timeout($message);
            }
            throw TransportException::network($message);
        }
        return ['status' => $status, 'body' => $text];
    }
}
