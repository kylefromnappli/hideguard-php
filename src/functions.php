<?php

declare(strict_types=1);

namespace HideGuard;

/*
 * The functions `@hideguard/node` exports beside its client, under the same names.
 * Loaded by Composer's `files` autoload.
 */

if (!function_exists(__NAMESPACE__ . '\\verifyCollectReply')) {
    /**
     * Whether a relayed `POST /api/v1/collect` reply is ours, current, and for this site.
     *
     * `siteId` and `environment` come from **your** configuration (or site() at boot), never from
     * the reply: a reply that names the site it is for proves nothing.
     *
     * @param array<string, mixed>|object $reply the reply as the page relayed it, decoded
     * @param array{siteId: string, environment: string, publicKeys: array<string, Ed25519PublicKey>,
     *              now?: \DateTimeInterface|int, toleranceSeconds?: int, clockSkewSeconds?: int} $options
     */
    function verifyCollectReply($reply, array $options): bool
    {
        return Signature::verifyReply($reply, $options, Signature::COLLECT_LABEL);
    }

    /**
     * The same check for a `POST /api/v1/verdict-public` reply. A collect reply does not pass it,
     * and a public verdict does not pass verifyCollectReply().
     *
     * @param array<string, mixed>|object $reply
     * @param array{siteId: string, environment: string, publicKeys: array<string, Ed25519PublicKey>,
     *              now?: \DateTimeInterface|int, toleranceSeconds?: int, clockSkewSeconds?: int} $options
     */
    function verifyPublicVerdictReply($reply, array $options): bool
    {
        return Signature::verifyReply($reply, $options, Signature::PUBLIC_VERDICT_LABEL);
    }

    /**
     * Whether a behaviour-flush acknowledgement is ours and answers the batch you sent.
     * `documentId` and `batchId` are the ones **you** sent; the reply is checked against them.
     *
     * @param array<string, mixed>|object $reply
     * @param array{siteId: string, environment: string, documentId: string, batchId: string,
     *              publicKeys: array<string, Ed25519PublicKey>, now?: \DateTimeInterface|int,
     *              toleranceSeconds?: int, clockSkewSeconds?: int} $options
     */
    function verifyBehaviorAck($reply, array $options): bool
    {
        return Signature::verifyAck($reply, $options);
    }

    /**
     * The key set the verifiers take, built from `$hg->signingKeys()['keys']` (or from keys you
     * keep in configuration). Load it once at boot, not per request.
     *
     * Throws on an entry that is not an Ed25519 public key in PEM rather than skipping it: a key
     * set quietly smaller than the one published reads, from the outside, as HideGuard refusing
     * your replies.
     *
     * @param list<array{alg: string, kid: string, publicKey: string}> $keys
     * @return array<string, Ed25519PublicKey>
     * @throws HideGuardError invalid_argument
     * @throws \LogicException when neither ext-sodium nor paragonie/sodium_compat is available
     */
    function publicKeyMap(array $keys): array
    {
        if (!function_exists('sodium_crypto_sign_verify_detached')) {
            throw new \LogicException(
                'hideguard/php verifies signatures with libsodium: enable ext-sodium (bundled with PHP 7.2+) or require paragonie/sodium_compat'
            );
        }
        $map = [];
        foreach ($keys as $entry) {
            $entry = Json::record($entry);
            $kid = $entry !== null && array_key_exists('kid', $entry) ? $entry['kid'] : null;
            $label = is_scalar($kid) ? (string) $kid : 'without a kid';
            if ($entry === null || !is_string($kid) || $kid === '') {
                throw new HideGuardError(HideGuardError::INVALID_ARGUMENT, "signing key {$label} has no kid", ['field' => 'kid']);
            }
            $pem = array_key_exists('publicKey', $entry) ? $entry['publicKey'] : null;
            if (!is_string($pem)) {
                throw new HideGuardError(HideGuardError::INVALID_ARGUMENT, "signing key {$kid} is not a PEM public key", ['field' => 'publicKey']);
            }
            try {
                $key = Ed25519PublicKey::fromPem($pem);
            } catch (HideGuardError $error) {
                throw new HideGuardError(
                    HideGuardError::INVALID_ARGUMENT,
                    $error->getField() === 'alg' ? "signing key {$kid} is not an Ed25519 key" : "signing key {$kid} is not a PEM public key",
                    ['field' => $error->getField(), 'previous' => $error]
                );
            }
            if ((array_key_exists('alg', $entry) ? $entry['alg'] : null) !== 'ed25519') {
                throw new HideGuardError(HideGuardError::INVALID_ARGUMENT, "signing key {$kid} is not an Ed25519 key", ['field' => 'alg']);
            }
            $map[$kid] = $key;
        }
        return $map;
    }

    /** @param mixed $value */
    function isHideGuardError($value): bool
    {
        return $value instanceof HideGuardError;
    }
}
