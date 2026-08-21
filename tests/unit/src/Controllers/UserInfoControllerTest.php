<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers;

use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Error\UserNotFound;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Controllers\Traits\RequestTrait;
use SimpleSAML\Module\oidc\Controllers\UserInfoController;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\ResourceServer;
use SimpleSAML\Module\oidc\Services\ErrorResponder;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Utils\Routes;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;

/**
 * @covers \SimpleSAML\Module\oidc\Controllers\UserInfoController
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
    protected MockObject $routesMock;
    protected MockObject $symfonyRequestMock;
    protected MockObject $symfonyResponseMock;
    protected MockObject $responseHeaderBagMock;
    protected MockObject $httpFoundationFactoryMock;
    protected MockObject $psrHttpFactoryMock;

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

        $this->routesMock = $this->createMock(Routes::class);
        $this->routesMock->method('newJsonResponse')->willReturnCallback(
            fn (
                array|null $data = null,
                int $status = 200,
                array $headers = [],
                bool $json = false,
            ) => new JsonResponse($data, $status, $headers, $json),
        );

        $this->symfonyRequestMock = $this->createMock(\Symfony\Component\HttpFoundation\Request::class);
        $this->symfonyResponseMock = $this->createMock(\Symfony\Component\HttpFoundation\Response::class);
        $this->responseHeaderBagMock = $this->createMock(ResponseHeaderBag::class);
        $this->symfonyResponseMock->headers = $this->responseHeaderBagMock;

        $this->httpFoundationFactoryMock = $this->createMock(HttpFoundationFactory::class);
        $this->httpFoundationFactoryMock->method('createResponse')->willReturn($this->symfonyResponseMock);
        $this->psrHttpBridgeMock->method('getHttpFoundationFactory')->willReturn($this->httpFoundationFactoryMock);

        $this->psrHttpFactoryMock = $this->createMock(PsrHttpFactory::class);
        $this->psrHttpFactoryMock->method('createRequest')->willReturn($this->serverRequestMock);
        $this->psrHttpBridgeMock->method('getPsrHttpFactory')->willReturn($this->psrHttpFactoryMock);
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
            $this->routesMock,
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
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \SimpleSAML\Error\UserNotFound
     */
    public function testItReturnsExtractedClaims(): void
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

        $response = $this->mock()->__invoke($this->serverRequestMock);
        $this->assertInstanceOf(JsonResponse::class, $response);
        $this->assertSame(
            ['email' => 'userid@localhost.localdomain'],
            json_decode((string) $response->getContent(), true),
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
        $corsResponseMock = $this->createMock(ResponseInterface::class);

        $userInfoControllerMock = $this->getMockBuilder(UserInfoController::class)
            ->setConstructorArgs([
                $this->resourceServerMock,
                $this->accessTokenRepositoryMock,
                $this->userRepositoryMock,
                $this->allowedOriginRepositoryMock,
                $this->claimTranslatorExtractorMock,
                $this->psrHttpBridgeMock,
                $this->errorResponderMock,
                $this->routesMock,
            ])
            ->onlyMethods(['handleCors'])
            ->getMock();

        $userInfoControllerMock->expects($this->once())
            ->method('handleCors')
            ->with($this->serverRequestMock)
            ->willReturn($corsResponseMock);

        $response = $userInfoControllerMock->__invoke($this->serverRequestMock);
        $this->assertSame($this->symfonyResponseMock, $response);
    }

    public function testItUsesRequestTrait(): void
    {
        $this->assertContains(RequestTrait::class, class_uses(UserInfoController::class));
    }

    public function testItAlwaysReturnsAccessControlAllowOrigin(): void
    {
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

        $response = $this->mock()->userInfo($this->symfonyRequestMock);
        $this->assertTrue($response->headers->has('Access-Control-Allow-Origin'));
        $this->assertSame('*', $response->headers->get('Access-Control-Allow-Origin'));
    }
}
