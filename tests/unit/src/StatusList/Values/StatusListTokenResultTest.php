<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\StatusList\Values;

use DateTimeImmutable;
use DateTimeZone;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListTokenResult;

#[CoversClass(StatusListTokenResult::class)]
class StatusListTokenResultTest extends TestCase
{
    protected function sut(
        string $token = 'header.payload.signature',
        int $ttlSeconds = 43200,
        string $issuedAt = '2026-08-01 12:00:00',
        string $expiresAt = '2026-08-08 12:00:00',
    ): StatusListTokenResult {
        return new StatusListTokenResult(
            $token,
            $ttlSeconds,
            new DateTimeImmutable($issuedAt, new DateTimeZone('UTC')),
            new DateTimeImmutable($expiresAt, new DateTimeZone('UTC')),
        );
    }

    protected function moment(string $moment): DateTimeImmutable
    {
        return new DateTimeImmutable($moment, new DateTimeZone('UTC'));
    }

    public function testCarriesWhatItWasGiven(): void
    {
        $result = $this->sut();

        $this->assertSame('header.payload.signature', $result->getToken());
        $this->assertSame(43200, $result->getTtlSeconds());
        $this->assertSame('2026-08-01 12:00:00', $result->getIssuedAt()->format('Y-m-d H:i:s'));
        $this->assertSame('2026-08-08 12:00:00', $result->getExpiresAt()->format('Y-m-d H:i:s'));
    }

    public function testTheEntityTagIsQuotedAndDerivedFromTheToken(): void
    {
        $this->assertMatchesRegularExpression('/^"[0-9a-f]{64}"$/', $this->sut()->getEntityTag());

        $this->assertSame($this->sut()->getEntityTag(), $this->sut()->getEntityTag());
        $this->assertNotSame($this->sut()->getEntityTag(), $this->sut('other.token.here')->getEntityTag());
    }

    /**
     * An encoded body and an unencoded one are different representations, so a shared cache holding both
     * has to be able to tell them apart.
     */
    public function testTheEntityTagNamesTheContentCoding(): void
    {
        $this->assertNotSame($this->sut()->getEntityTag(), $this->sut()->getEntityTag('gzip'));
        $this->assertStringEndsWith('-gzip"', $this->sut()->getEntityTag('gzip'));
    }

    /**
     * The `ttl` is what the specification offers a Relying Party, so it is the ceiling while the token
     * has longer to live than that.
     */
    public function testCachesForTheTimeToLiveWhileThereIsRoomForIt(): void
    {
        $this->assertSame(43200, $this->sut()->getMaxAgeSeconds($this->moment('2026-08-01 12:00:00')));
    }

    /**
     * Close to expiry the token's own remaining life is shorter than the `ttl`, and a cached copy must
     * not outlive the token: past expiry it is not stale but invalid.
     */
    public function testNeverCachesPastTheTokensOwnExpiry(): void
    {
        $this->assertSame(
            3600,
            $this->sut()->getMaxAgeSeconds($this->moment('2026-08-08 11:00:00')),
        );
    }

    public function testAnAlreadyExpiredTokenIsNotCacheableAtAll(): void
    {
        $this->assertSame(0, $this->sut()->getMaxAgeSeconds($this->moment('2026-08-09 12:00:00')));
    }
}
