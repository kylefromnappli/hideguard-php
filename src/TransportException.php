<?php

declare(strict_types=1);

namespace HideGuard;

/**
 * What a transport throws when no HTTP answer arrived. The client turns it into a
 * HideGuardError with code `timeout` or `network`; any other exception a custom transport throws
 * is read as `network`.
 */
final class TransportException extends \RuntimeException
{
    /** @var bool */
    private $timedOut;

    public function __construct(string $message, bool $timedOut = false, ?\Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
        $this->timedOut = $timedOut;
    }

    public static function timeout(string $message, ?\Throwable $previous = null): self
    {
        return new self($message, true, $previous);
    }

    public static function network(string $message, ?\Throwable $previous = null): self
    {
        return new self($message, false, $previous);
    }

    public function timedOut(): bool
    {
        return $this->timedOut;
    }
}
