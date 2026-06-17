<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Services;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\AuthCodeRepository;
use SimpleSAML\Module\oidc\Repositories\IssuerStateRepository;
use SimpleSAML\Module\oidc\Repositories\PushedAuthorizationRequestRepository;
use SimpleSAML\Module\oidc\Repositories\RefreshTokenRepository;
use SimpleSAML\Module\oidc\Services\ExpiredEntriesCleaner;

#[CoversClass(ExpiredEntriesCleaner::class)]
class ExpiredEntriesCleanerTest extends TestCase
{
    private AccessTokenRepository&MockObject $accessTokenRepositoryMock;
    private AuthCodeRepository&MockObject $authCodeRepositoryMock;
    private RefreshTokenRepository&MockObject $refreshTokenRepositoryMock;
    private IssuerStateRepository&MockObject $issuerStateRepositoryMock;
    private PushedAuthorizationRequestRepository&MockObject $pushedAuthorizationRequestRepositoryMock;

    protected function setUp(): void
    {
        $this->accessTokenRepositoryMock = $this->createMock(AccessTokenRepository::class);
        $this->authCodeRepositoryMock = $this->createMock(AuthCodeRepository::class);
        $this->refreshTokenRepositoryMock = $this->createMock(RefreshTokenRepository::class);
        $this->issuerStateRepositoryMock = $this->createMock(IssuerStateRepository::class);
        $this->pushedAuthorizationRequestRepositoryMock = $this->createMock(
            PushedAuthorizationRequestRepository::class,
        );
    }

    public function testItIsInitializable(): void
    {
        $cleaner = new ExpiredEntriesCleaner(
            $this->accessTokenRepositoryMock,
            $this->authCodeRepositoryMock,
            $this->refreshTokenRepositoryMock,
            $this->issuerStateRepositoryMock,
            $this->pushedAuthorizationRequestRepositoryMock,
        );

        $this->assertInstanceOf(ExpiredEntriesCleaner::class, $cleaner);
    }

    public function testCleanRemovesExpiredAndInvalidEntries(): void
    {
        $this->accessTokenRepositoryMock->expects($this->once())
            ->method('removeExpired');

        $this->authCodeRepositoryMock->expects($this->once())
            ->method('removeExpired');

        $this->refreshTokenRepositoryMock->expects($this->once())
            ->method('removeExpired');

        $this->issuerStateRepositoryMock->expects($this->once())
            ->method('removeInvalid');

        $this->pushedAuthorizationRequestRepositoryMock->expects($this->once())
            ->method('removeExpired');

        $cleaner = new ExpiredEntriesCleaner(
            $this->accessTokenRepositoryMock,
            $this->authCodeRepositoryMock,
            $this->refreshTokenRepositoryMock,
            $this->issuerStateRepositoryMock,
            $this->pushedAuthorizationRequestRepositoryMock,
        );

        $cleaner->clean();
    }
}
