<?php

declare(strict_types=1);

namespace HideGuard;

/**
 * Every failure of a call, with the code saying which kind.
 *
 * - `http` — the collector answered outside 2xx; getStatus() and getBody() say how.
 * - `timeout` — no complete answer within `timeoutMs`. getStatus() is null.
 * - `network` — the request never got an answer (DNS, refused, reset, TLS). getStatus() is null.
 * - `invalid_response` — a 2xx whose body is not the shape this route returns.
 * - `card_number` — a field looked like a card number; **nothing was sent**.
 * - `invalid_argument` — the call could not be a request at all; nothing was sent.
 *
 * The same codes `@hideguard/node` throws, minus `aborted`: PHP has no AbortSignal, so nothing
 * here can be aborted from outside a call.
 *
 * The client never swallows one. A checkout that must keep working when HideGuard does not
 * answer is the merchant's decision and is a try/catch at the call site (see README); an SDK
 * that decided it for them would also hide the 401 from a rotated secret.
 */
class HideGuardError extends \RuntimeException
{
    const HTTP = 'http';
    const TIMEOUT = 'timeout';
    const NETWORK = 'network';
    const INVALID_RESPONSE = 'invalid_response';
    const CARD_NUMBER = 'card_number';
    const INVALID_ARGUMENT = 'invalid_argument';

    /** @var string */
    private $errorCode;

    /** @var int|null */
    private $status;

    /** @var mixed */
    private $body;

    /** @var string|null */
    private $field;

    /**
     * @param array{status?: int|null, body?: mixed, field?: string|null, previous?: \Throwable|null} $details
     */
    public function __construct(string $errorCode, string $message, array $details = [])
    {
        $previous = isset($details['previous']) ? $details['previous'] : null;
        parent::__construct($message, 0, $previous);
        $this->errorCode = $errorCode;
        $this->status = isset($details['status']) ? $details['status'] : null;
        $this->body = array_key_exists('body', $details) ? $details['body'] : null;
        $this->field = isset($details['field']) ? $details['field'] : null;
    }

    /** One of the class constants: `http`, `timeout`, `network`, `invalid_response`, `card_number`, `invalid_argument`. */
    public function getErrorCode(): string
    {
        return $this->errorCode;
    }

    /** The HTTP status, or null when there was no HTTP answer (network, timeout, refusals). */
    public function getStatus()
    {
        return $this->status;
    }

    /** The parsed reply body (decoded JSON when it was JSON, the text otherwise), or null. */
    public function getBody()
    {
        return $this->body;
    }

    /** For `card_number` and `invalid_argument`: the field at fault, when one is. */
    public function getField()
    {
        return $this->field;
    }
}
