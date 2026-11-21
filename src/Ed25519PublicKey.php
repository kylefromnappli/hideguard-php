<?php

declare(strict_types=1);

namespace HideGuard;

/**
 * One public key the verifiers trust. Built by `publicKeyMap()` from the PEM keys
 * `signingKeys()` publishes, or with `fromPem()` / `fromRaw()` from keys kept in configuration.
 *
 * A type of its own rather than a string so that a PEM text passed where a key was expected is
 * a type error at the call, not a verifier that quietly refuses every reply.
 */
final class Ed25519PublicKey
{
    /** The DER prefix of an Ed25519 SubjectPublicKeyInfo: SEQUENCE, AlgorithmIdentifier 1.3.101.112, BIT STRING. */
    const SPKI_PREFIX = "\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00";

    /** @var string 32 raw bytes */
    private $bytes;

    private function __construct(string $bytes)
    {
        $this->bytes = $bytes;
    }

    /**
     * From a `-----BEGIN PUBLIC KEY-----` PEM (SPKI), as `GET /api/v1/signing-key` serves it.
     *
     * @throws HideGuardError invalid_argument, field `publicKey` when it is not a PEM public key
     *                        and `alg` when it is one but not Ed25519
     */
    public static function fromPem(string $pem): self
    {
        if (!preg_match('/-----BEGIN PUBLIC KEY-----([A-Za-z0-9+\/=\s]+)-----END PUBLIC KEY-----/', $pem, $match)) {
            throw new HideGuardError(HideGuardError::INVALID_ARGUMENT, 'not a PEM public key', ['field' => 'publicKey']);
        }
        $der = base64_decode((string) preg_replace('/\s+/', '', $match[1]), true);
        if ($der === false || $der === '') {
            throw new HideGuardError(HideGuardError::INVALID_ARGUMENT, 'not a PEM public key', ['field' => 'publicKey']);
        }
        if (strlen($der) !== 44 || substr($der, 0, 12) !== self::SPKI_PREFIX) {
            throw new HideGuardError(HideGuardError::INVALID_ARGUMENT, 'not an Ed25519 public key', ['field' => 'alg']);
        }
        return new self(substr($der, 12));
    }

    /** From the 32 raw bytes of the key. */
    public static function fromRaw(string $bytes): self
    {
        if (strlen($bytes) !== 32) {
            throw new HideGuardError(HideGuardError::INVALID_ARGUMENT, 'an Ed25519 public key is 32 bytes', ['field' => 'publicKey']);
        }
        return new self($bytes);
    }

    /** The 32 raw bytes. */
    public function bytes(): string
    {
        return $this->bytes;
    }
}
