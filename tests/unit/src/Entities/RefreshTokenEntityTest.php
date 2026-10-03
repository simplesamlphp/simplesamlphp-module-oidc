<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Entities;

use DateTimeImmutable;
use DateTimeZone;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\RefreshTokenEntityInterface;
use SimpleSAML\Module\oidc\Entities\RefreshTokenEntity;

/**
 * @covers \SimpleSAML\Module\oidc\Entities\RefreshTokenEntity
 */
#[AllowMockObjectsWithoutExpectations]
class RefreshTokenEntityTest extends TestCase
{
    protected string $id;

    protected DateTimeImmutable $expiryDateTime;

    protected MockObject $accessTokenEntityMock;

    protected false $isRevoked;

    protected string $authCodeId;


    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->id = 'id';
        $this->expiryDateTime = new DateTimeImmutable('1970-01-01 00:00:00', new DateTimeZone('UTC'));
        $this->accessTokenEntityMock = $this->createMock(AccessTokenEntity::class);
        $this->accessTokenEntityMock->method('getIdentifier')->willReturn('access_token_id');
        $this->isRevoked = false;
        $this->authCodeId = 'auth_code_id';
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    protected function mock(): RefreshTokenEntityInterface
    {
        return new RefreshTokenEntity(
            $this->id,
            $this->expiryDateTime,
            $this->accessTokenEntityMock,
            $this->authCodeId,
            $this->isRevoked,
        );
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            RefreshTokenEntity::class,
            $this->mock(),
        );
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCanGetState(): void
    {
        $this->assertSame(
            $this->mock()->getState(),
            [
                'id' => $this->id,
                'expires_at' => '1970-01-01 00:00:00',
                'access_token_id' => $this->accessTokenEntityMock->getIdentifier(),
                'is_revoked' => $this->isRevoked,
                'auth_code_id' => $this->authCodeId,
            ],
        );
    }


    /**
     * The expiry is made in PHP's default time zone and read back as UTC, so it is written out in UTC. As the wall
     * clock of a server west of UTC, it would read back hours early.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testWritesTheExpiryInUtc(): void
    {
        $this->expiryDateTime = new DateTimeImmutable('2026-10-03 12:10:00', new DateTimeZone('America/New_York'));

        $this->assertSame('2026-10-03 16:10:00', $this->mock()->getState()['expires_at']);
    }
}
