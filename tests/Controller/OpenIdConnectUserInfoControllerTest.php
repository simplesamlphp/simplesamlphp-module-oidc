<?php

namespace SimpleSAML\Test\Module\oidc\Controller;

use Laminas\Diactoros\ServerRequest;
use League\OAuth2\Server\ResourceServer;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Controller\OpenIdConnectUserInfoController;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Entity\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entity\UserEntity;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;

/**
 * @covers \SimpleSAML\Module\oidc\Controller\OpenIdConnectUserInfoController
 */
class OpenIdConnectUserInfoControllerTest extends TestCase
{
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $resourceServerMock;
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $accessTokenRepositoryMock;
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $userRepositoryMock;
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $allowedOriginRepositoryMock;
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $claimTranslatorExtractorMock;
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $serverRequestMock;
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $authorizationServerRequestMock;
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $accessTokenEntityMock;
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $userEntityMock;

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
    }

    protected function prepareMockedInstance(): OpenIdConnectUserInfoController
    {
        return new OpenIdConnectUserInfoController(
            $this->resourceServerMock,
            $this->accessTokenRepositoryMock,
            $this->userRepositoryMock,
            $this->allowedOriginRepositoryMock,
            $this->claimTranslatorExtractorMock
        );
    }

    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            OpenIdConnectUserInfoController::class,
            $this->prepareMockedInstance()
        );
    }

    // TODO mivanci nastavi
//    public function testItReturnsUserClaims(): void
//    {
//        $this->serverRequestMock->expects($this->once())->method('getMethod')->willReturn('GET');
//        $this->authorizationServerRequestMock
//            ->expects($this->atLeast(2))
//            ->method('getAttribute')
//            ->willReturnCallback(function ($argument) {
//                $argumentValueMap = [
//                    'oauth_access_token_id' => 'tokenid',
//                    'oauth_scopes' => ['openid', 'email']
//                ];
//
//                if (array_key_exists($argument, $argumentValueMap)) {
//                    return $argumentValueMap[$argument];
//                }
//
//                return null;
//            });
//        $this->resourceServerMock
//            ->expects($this->once())
//            ->method('validateAuthenticatedRequest')
//            ->willReturn($this->authorizationServerRequestMock);
//        $this->accessTokenEntityMock
//            ->expects($this->once())
//            ->method('getUserIdentifier')
//            ->willReturn('userid');
//        $this->accessTokenEntityMock
//            ->expects($this->once())
//            ->method('getRequestedClaims')
//            ->willReturn([]);
//        $this->accessTokenRepositoryMock
//            ->expects($this->once())
//            ->method('findById')
//            ->willReturn($this->accessTokenEntityMock);
//        $this->userEntityMock
//            ->expects($this->once())
//            ->method('getClaims')
//            ->willReturn(['mail' => ['userid@localhost.localdomain']]);
//        $this->userRepositoryMock
//            ->expects($this->once())
//            ->method('getUserEntityByIdentifier')
//            ->with('userid')
//            ->willReturn($this->userEntityMock);
//        $this->claimTranslatorExtractorMock
//            ->expects($this->once())
//            ->method('extract')
//            ->with(['openid', 'email'], ['mail' => ['userid@localhost.localdomain']])
//            ->willReturn(['email' => 'userid@localhost.localdomain']);
//        $this->claimTranslatorExtractorMock
//            ->expects($this->once())
//            ->method('extractAdditionalUserInfoClaims')
//            ->with([], ['mail' => ['userid@localhost.localdomain']])
//            ->willReturn([]);
//
//        $this->assertSame(
//            ['email' => 'userid@localhost.localdomain'],
//            $this->prepareMockedInstance()->__invoke($this->serverRequestMock)->getPayload()
//        );
//    }
}
