<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controller;

use Laminas\Diactoros\ServerRequest;
use League\OAuth2\Server\ResourceServer;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Error\UserNotFound;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Controller\Traits\RequestTrait;
use SimpleSAML\Module\oidc\Controller\UserInfoController;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Services\ErrorResponder;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;

/**
 * @covers \SimpleSAML\Module\oidc\Controller\UserInfoController
 */
class UserInfoControllerTest extends TestCase
{
    protected MockObject $resourceServerMock;
    protected MockObject $accessTokenRepositoryMock;
    protected MockObject $userRepositoryMock;
    protected MockObject $allowedOriginRepositoryMock;
    protected MockObject $claimTranslatorExtractorMock;
    protected MockObject $serverRequestMock;
    protected MockObject $authorizationServerRequestMock;
    protected MockObject $accessTokenEntityMock;
    protected MockObject $userEntityMock;
    protected MockObject $psrHttpBridgeMock;
    protected MockObject $errorResponderMock;

    protected function setUp(): void
    {
        $this->resourceServerMock = $this->createMock(ResourceServer::class);
        $this->accessTokenRepositoryMock = $this->createMock(AccessTokenRepository::class);
        $this->userRepositoryMock = $this->createMock(UserRepository::class);
        $this->allowedOriginRepositoryMock = $this->createMock(AllowedOriginRepository::class);
        $this->claimTranslatorExtractorMock = $this->createMock(ClaimTranslatorExtractor::class);

        $this->serverRequestMock = $this->createMock(ServerRequest::class);
        $this->authorizationServerRequestMock = $this->createMock(ServerRequestInterface::class);
        $this->accessTokenEntityMock = $this->createMock(AccessTokenEntity::class);
        $this->userEntityMock = $this->createMock(UserEntity::class);

        $this->psrHttpBridgeMock = $this->createMock(PsrHttpBridge::class);
        $this->errorResponderMock = $this->createMock(ErrorResponder::class);
    }

    protected function mock(): UserInfoController
    {
        return new UserInfoController(
            $this->resourceServerMock,
            $this->accessTokenRepositoryMock,
            $this->userRepositoryMock,
            $this->allowedOriginRepositoryMock,
            $this->claimTranslatorExtractorMock,
            $this->psrHttpBridgeMock,
            $this->errorResponderMock,
        );
    }

    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            UserInfoController::class,
            $this->mock(),
        );
    }

    /**
     * @throws \SimpleSAML\Error\UserNotFound
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    public function testItReturnsUserClaims(): void
    {
        $this->serverRequestMock->expects($this->once())->method('getMethod')->willReturn('GET');
        $this->authorizationServerRequestMock
            ->expects($this->atLeast(2))
            ->method('getAttribute')
            ->willReturnCallback(function ($argument) {
                $argumentValueMap = [
                    'oauth_access_token_id' => 'tokenid',
                    'oauth_scopes' => ['openid', 'email'],
                ];

                if (array_key_exists($argument, $argumentValueMap)) {
                    return $argumentValueMap[$argument];
                }

                return null;
            });
        $this->resourceServerMock
            ->expects($this->once())
            ->method('validateAuthenticatedRequest')
            ->willReturn($this->authorizationServerRequestMock);
        $this->accessTokenEntityMock
            ->expects($this->once())
            ->method('getUserIdentifier')
            ->willReturn('userid');
        $this->accessTokenEntityMock
            ->expects($this->once())
            ->method('getRequestedClaims')
            ->willReturn([]);
        $this->accessTokenRepositoryMock
            ->expects($this->once())
            ->method('findById')
            ->willReturn($this->accessTokenEntityMock);
        $this->userEntityMock
            ->expects($this->atLeast(2))
            ->method('getClaims')
            ->willReturn(['mail' => ['userid@localhost.localdomain']]);
        $this->userRepositoryMock
            ->expects($this->once())
            ->method('getUserEntityByIdentifier')
            ->with('userid')
            ->willReturn($this->userEntityMock);
        $this->claimTranslatorExtractorMock
            ->expects($this->once())
            ->method('extract')
            ->with(['openid', 'email'], ['mail' => ['userid@localhost.localdomain']])
            ->willReturn(['email' => 'userid@localhost.localdomain']);
        $this->claimTranslatorExtractorMock
            ->expects($this->once())
            ->method('extractAdditionalUserInfoClaims')
            ->with([], ['mail' => ['userid@localhost.localdomain']])
            ->willReturn([]);

        $this->assertSame(
            ['email' => 'userid@localhost.localdomain'],
            $this->mock()->__invoke($this->serverRequestMock)->getPayload(),
        );
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    public function testItThrowsIfAccessTokenNotFound(): void
    {
        $this->serverRequestMock->expects($this->once())->method('getMethod')->willReturn('GET');
        $this->authorizationServerRequestMock
            ->expects($this->atLeast(2))
            ->method('getAttribute')
            ->willReturnCallback(function ($argument) {
                $argumentValueMap = [
                    'oauth_access_token_id' => 'tokenid',
                    'oauth_scopes' => ['openid', 'email'],
                ];

                if (array_key_exists($argument, $argumentValueMap)) {
                    return $argumentValueMap[$argument];
                }

                return null;
            });
        $this->resourceServerMock
            ->expects($this->once())
            ->method('validateAuthenticatedRequest')
            ->willReturn($this->authorizationServerRequestMock);
        $this->accessTokenRepositoryMock
            ->expects($this->once())
            ->method('findById')
            ->willReturn(null);

        $this->expectException(UserNotFound::class);
        $this->mock()->__invoke($this->serverRequestMock);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    public function testItThrowsIfUserNotFound(): void
    {
        $this->serverRequestMock->expects($this->once())->method('getMethod')->willReturn('GET');
        $this->authorizationServerRequestMock
            ->expects($this->atLeast(2))
            ->method('getAttribute')
            ->willReturnCallback(function ($argument) {
                $argumentValueMap = [
                    'oauth_access_token_id' => 'tokenid',
                    'oauth_scopes' => ['openid', 'email'],
                ];

                if (array_key_exists($argument, $argumentValueMap)) {
                    return $argumentValueMap[$argument];
                }

                return null;
            });
        $this->resourceServerMock
            ->expects($this->once())
            ->method('validateAuthenticatedRequest')
            ->willReturn($this->authorizationServerRequestMock);
        $this->accessTokenEntityMock
            ->expects($this->once())
            ->method('getUserIdentifier')
            ->willReturn('userid');
        $this->accessTokenRepositoryMock
            ->expects($this->once())
            ->method('findById')
            ->willReturn($this->accessTokenEntityMock);
        $this->userRepositoryMock
            ->expects($this->once())
            ->method('getUserEntityByIdentifier')
            ->with('userid')
            ->willReturn(null);

        $this->expectException(UserNotFound::class);
        $this->mock()->__invoke($this->serverRequestMock);
    }

    public function testItHandlesCorsRequest(): void
    {
        $this->serverRequestMock->expects($this->once())->method('getMethod')->willReturn('OPTIONS');
        $userInfoControllerMock = $this->getMockBuilder(UserInfoController::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['handleCors'])
            ->getMock();
        $userInfoControllerMock->expects($this->once())->method('handleCors');

        $userInfoControllerMock->__invoke($this->serverRequestMock);
    }

    public function testItUsesRequestTrait(): void
    {
        $this->assertContains(RequestTrait::class, class_uses(UserInfoController::class));
    }
}
