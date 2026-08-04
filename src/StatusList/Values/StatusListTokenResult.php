<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\StatusList\Values;

use DateTimeImmutable;

/**
 * A Status List Token which is ready to be served, together with what the response has to say about it.
 *
 * The caching values are derived here rather than at the endpoint because they are properties of the
 * token: how long it may be reused is what its own `ttl` claim conveys, and it must never be held past
 * the expiry it carries.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\StatusList\Values\StatusListTokenResultTest
 */
class StatusListTokenResult
{
    public function __construct(
        protected readonly string $token,
        protected readonly int $ttlSeconds,
        protected readonly DateTimeImmutable $issuedAt,
        protected readonly DateTimeImmutable $expiresAt,
    ) {
    }

    public function getToken(): string
    {
        return $this->token;
    }

    public function getTtlSeconds(): int
    {
        return $this->ttlSeconds;
    }

    public function getIssuedAt(): DateTimeImmutable
    {
        return $this->issuedAt;
    }

    public function getExpiresAt(): DateTimeImmutable
    {
        return $this->expiresAt;
    }

    /**
     * A strong validator over the exact bytes served.
     *
     * Derived from the token rather than from the list's content hash or a change counter, both of
     * which would tell a client something about how often the list changes. Two responses carrying the
     * same token are byte identical whatever produced them, which is precisely what a strong entity tag
     * asserts.
     *
     * @param ?string $contentCoding Coding the body was encoded with, which forms part of the tag. An
     * encoded body and an unencoded one are different representations, so a shared cache holding both
     * needs to be able to tell them apart even though the token inside is the same.
     */
    public function getEntityTag(?string $contentCoding = null): string
    {
        return sprintf(
            '"%s%s"',
            hash('sha256', $this->token),
            $contentCoding === null ? '' : '-' . $contentCoding,
        );
    }

    /**
     * How long a cache may hold this response.
     *
     * The token's `ttl` is what the specification offers Relying Parties, so it is the ceiling -- but a
     * cached copy must never outlive the token's own expiry, since past that point it is not merely
     * stale but invalid. Never negative: an already expired token is served with no reuse allowed at
     * all, rather than with a nonsensical header.
     */
    public function getMaxAgeSeconds(DateTimeImmutable $now): int
    {
        $secondsUntilExpiry = $this->expiresAt->getTimestamp() - $now->getTimestamp();

        return max(0, min($this->ttlSeconds, $secondsUntilExpiry));
    }
}
