<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers;

use DateTimeImmutable;
use DateTimeZone;
use League\OAuth2\Server\Exception\OAuthServerException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Controllers\PushedAuthorizationController;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Entities\PushedAuthorizationRequestEntity;
use SimpleSAML\Module\oidc\Factories\Entities\PushedAuthorizationRequestEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Repositories\PushedAuthorizationRequestRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequestObjectRule;
use SimpleSAML\Module\oidc\Services\ErrorResponder;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\AuthenticatedOAuth2ClientResolver;
use SimpleSAML\Module\oidc\ValueAbstracts\ResolvedClientAuthenticationMethod;
use SimpleSAML\OpenID\Codebooks\ClientAuthenticationMethodsEnum;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

#[CoversClass(PushedAuthorizationController::class)]
#[UsesClass(Result::class)]
#[UsesClass(ResultBag::class)]
#[UsesClass(ResolvedClientAuthenticationMethod::class)]
class PushedAuthorizationControllerTest extends TestCase
{
    protected MockObject $authenticatedOAuth2ClientResolverMock;
    protected MockObject $pushedAuthorizationRequestRepositoryMock;
    protected MockObject $pushedAuthorizationRequestEntityFactoryMock;
    protected MockObject $requestRulesManagerMock;
    protected MockObject $psrHttpBridgeMock;
    protected MockObject $errorResponderMock;
    protected Helpers $helpers;
    protected MockObject $loggerMock;

    protected MockObject $serverRequestMock;
    protected MockObject $responseMock;
    protected MockObject $responseFactoryMock;
    protected MockObject $streamMock;
    protected MockObject $clientMock;
    protected MockObject $parEntityMock;
    protected MockObject $resultBagMock;

    protected function setUp(): void
    {
        $this->authenticatedOAuth2ClientResolverMock = $this->createMock(AuthenticatedOAuth2ClientResolver::class);
        $this->pushedAuthorizationRequestRepositoryMock = $this->createMock(
            PushedAuthorizationRequestRepository::class,
        );
        $this->pushedAuthorizationRequestEntityFactoryMock = $this->createMock(
            PushedAuthorizationRequestEntityFactory::class,
        );
        $this->requestRulesManagerMock = $this->createMock(RequestRulesManager::class);
        $this->psrHttpBridgeMock = $this->createMock(PsrHttpBridge::class);
        $this->errorResponderMock = $this->createMock(ErrorResponder::class);
        $this->helpers = new Helpers();
        $this->loggerMock = $this->createMock(LoggerService::class);

        $this->serverRequestMock = $this->createMock(ServerRequestInterface::class);
        $this->responseMock = $this->createMock(ResponseInterface::class);
        $this->responseFactoryMock = $this->createMock(ResponseFactoryInterface::class);
        $this->streamMock = $this->createMock(StreamInterface::class);

        $this->responseMock->method('getBody')->willReturn($this->streamMock);
        $this->responseMock->method('withStatus')->willReturn($this->responseMock);
        $this->responseMock->method('withHeader')->willReturn($this->responseMock);
        $this->responseFactoryMock->method('createResponse')->willReturn($this->responseMock);
        $this->psrHttpBridgeMock->method('getResponseFactory')->willReturn($this->responseFactoryMock);

        $this->clientMock = $this->createMock(ClientEntityInterface::class);
        $this->clientMock->method('getIdentifier')->willReturn('client123');

        $this->parEntityMock = $this->createMock(PushedAuthorizationRequestEntity::class);
        $this->parEntityMock->method('getRequestUri')
            ->willReturn(PushedAuthorizationRequestEntityFactory::REQUEST_URI_PREFIX . 'abc123');
        $this->parEntityMock->method('getExpiresAt')
            ->willReturn(new DateTimeImmutable('+5 minutes', new DateTimeZone('UTC')));

        $this->resultBagMock = $this->createMock(ResultBag::class);
        $this->requestRulesManagerMock->method('check')->willReturn($this->resultBagMock);
    }

    protected function sut(): PushedAuthorizationController
    {
        return new PushedAuthorizationController(
            $this->authenticatedOAuth2ClientResolverMock,
            $this->pushedAuthorizationRequestRepositoryMock,
            $this->pushedAuthorizationRequestEntityFactoryMock,
            $this->requestRulesManagerMock,
            $this->psrHttpBridgeMock,
            $this->errorResponderMock,
            $this->helpers,
            $this->loggerMock,
        );
    }

    protected function prepareAuthenticatedClient(
        ClientAuthenticationMethodsEnum $method = ClientAuthenticationMethodsEnum::ClientSecretPost,
    ): void {
        $resolvedAuth = new ResolvedClientAuthenticationMethod($this->clientMock, $method);
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')->willReturn($resolvedAuth);
    }

    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(PushedAuthorizationController::class, $this->sut());
    }

    public function testMethodMustBePost(): void
    {
        $this->serverRequestMock->method('getMethod')->willReturn('GET');

        $this->responseMock->expects($this->once())->method('withStatus')
            ->with(405)->willReturn($this->responseMock);
        $this->responseMock->expects($this->once())->method('withHeader')
            ->with('Allow', 'POST')->willReturn($this->responseMock);

        $response = $this->sut()->__invoke($this->serverRequestMock);
        $this->assertSame($this->responseMock, $response);
    }

    public function testClientAuthenticationFailureThrows(): void
    {
        $this->serverRequestMock->method('getMethod')->willReturn('POST');
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')->willReturn(null);

        $this->expectException(OidcServerException::class);
        $this->sut()->__invoke($this->serverRequestMock);
    }

    public function testConfidentialClientMustAuthenticate(): void
    {
        $this->serverRequestMock->method('getMethod')->willReturn('POST');
        $this->clientMock->method('isConfidential')->willReturn(true);
        $this->prepareAuthenticatedClient(ClientAuthenticationMethodsEnum::None);

        $this->expectException(OidcServerException::class);
        $this->sut()->__invoke($this->serverRequestMock);
    }

    public function testRejectsRequestUriInBody(): void
    {
        $this->serverRequestMock->method('getMethod')->willReturn('POST');
        $this->prepareAuthenticatedClient();

        $this->serverRequestMock->method('getParsedBody')->willReturn([
            'request_uri' => 'some-uri',
        ]);

        $this->expectException(OidcServerException::class);
        $this->sut()->__invoke($this->serverRequestMock);
    }

    public function testRejectsClientIdParamWhichDoesNotMatchAuthenticatedClient(): void
    {
        $this->serverRequestMock->method('getMethod')->willReturn('POST');
        $this->prepareAuthenticatedClient();

        $this->serverRequestMock->method('getParsedBody')->willReturn([
            'client_id' => 'otherClient',
        ]);

        $this->expectException(OidcServerException::class);
        $this->sut()->__invoke($this->serverRequestMock);
    }

    public function testHandlesValidParRequest(): void
    {
        $this->serverRequestMock->method('getMethod')->willReturn('POST');
        $this->prepareAuthenticatedClient();

        $params = [
            'client_id' => 'client123',
            'client_secret' => 'verysecret',
            'redirect_uri' => 'https://localhost/callback',
            'response_type' => 'code',
            'scope' => 'openid',
            'state' => 'xyz',
        ];
        $this->serverRequestMock->method('getParsedBody')->willReturn($params);

        // Client authentication params must not be persisted, while client_id is bound to the
        // authenticated client.
        $this->pushedAuthorizationRequestEntityFactoryMock->expects($this->once())
            ->method('buildNew')
            ->with(
                'client123',
                [
                    'client_id' => 'client123',
                    'redirect_uri' => 'https://localhost/callback',
                    'response_type' => 'code',
                    'scope' => 'openid',
                    'state' => 'xyz',
                ],
            )
            ->willReturn($this->parEntityMock);

        $this->pushedAuthorizationRequestRepositoryMock->expects($this->once())->method('persist')
            ->with($this->parEntityMock);

        $this->responseMock->expects($this->once())->method('withStatus')
            ->with(201)->willReturn($this->responseMock);

        $response = $this->sut()->__invoke($this->serverRequestMock);
        $this->assertSame($this->responseMock, $response);
    }

    public function testPersistsRequestObjectPayloadOnlyWhenJarIsUsed(): void
    {
        $this->serverRequestMock->method('getMethod')->willReturn('POST');
        $this->prepareAuthenticatedClient();

        $params = [
            'request' => 'token',
            'client_secret' => 'verysecret',
            'some_stray_param' => 'value',
        ];
        $this->serverRequestMock->method('getParsedBody')->willReturn($params);

        $requestObjectPayload = [
            'client_id' => 'client123',
            'redirect_uri' => 'https://localhost/callback',
            'response_type' => 'code',
            'scope' => 'openid',
        ];
        $requestObjectResult = new Result(RequestObjectRule::class, $requestObjectPayload);
        $this->resultBagMock->method('get')->with(RequestObjectRule::class)->willReturn($requestObjectResult);
        $this->resultBagMock->method('getOrFail')->with(RequestObjectRule::class)->willReturn($requestObjectResult);

        $this->pushedAuthorizationRequestEntityFactoryMock->expects($this->once())
            ->method('buildNew')
            ->with('client123', $requestObjectPayload)
            ->willReturn($this->parEntityMock);

        $this->pushedAuthorizationRequestRepositoryMock->expects($this->once())->method('persist');

        $this->sut()->__invoke($this->serverRequestMock);
    }

    public function testRejectsRequestObjectClientIdClaimWhichDoesNotMatchAuthenticatedClient(): void
    {
        $this->serverRequestMock->method('getMethod')->willReturn('POST');
        $this->prepareAuthenticatedClient();

        $this->serverRequestMock->method('getParsedBody')->willReturn(['request' => 'token']);

        $requestObjectResult = new Result(RequestObjectRule::class, ['client_id' => 'otherClient']);
        $this->resultBagMock->method('get')->with(RequestObjectRule::class)->willReturn($requestObjectResult);
        $this->resultBagMock->method('getOrFail')->with(RequestObjectRule::class)->willReturn($requestObjectResult);

        $this->expectException(OidcServerException::class);
        $this->sut()->__invoke($this->serverRequestMock);
    }

    public function testParReturnsJsonErrorResponseForOAuthServerException(): void
    {
        $requestMock = $this->createMock(Request::class);
        $psrHttpFactoryMock = $this->createMock(PsrHttpFactory::class);
        $psrHttpFactoryMock->method('createRequest')->willReturn($this->serverRequestMock);
        $this->psrHttpBridgeMock->method('getPsrHttpFactory')->willReturn($psrHttpFactoryMock);

        // Make __invoke throw an OidcServerException (client authentication failure).
        $this->serverRequestMock->method('getMethod')->willReturn('POST');
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')->willReturn(null);

        $jsonResponse = new JsonResponse();
        $this->errorResponderMock->expects($this->once())
            ->method('forExceptionJson')
            ->with($this->isInstanceOf(OAuthServerException::class))
            ->willReturn($jsonResponse);

        $this->assertSame($jsonResponse, $this->sut()->par($requestMock));
    }

    public function testParReturnsGenericJsonErrorResponseForUnexpectedThrowable(): void
    {
        $requestMock = $this->createMock(Request::class);
        $psrHttpFactoryMock = $this->createMock(PsrHttpFactory::class);
        $psrHttpFactoryMock->method('createRequest')->willReturn($this->serverRequestMock);
        $this->psrHttpBridgeMock->method('getPsrHttpFactory')->willReturn($psrHttpFactoryMock);

        $this->serverRequestMock->method('getMethod')->willReturn('POST');
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willThrowException(new \RuntimeException('some internal error'));

        $jsonResponse = new JsonResponse();
        $this->errorResponderMock->expects($this->once())
            ->method('forExceptionJson')
            ->with($this->callback(
                // Internal error details must not leak to the client.
                fn(OAuthServerException $exception): bool =>
                    !str_contains($exception->getMessage(), 'some internal error') &&
                    !str_contains((string)$exception->getHint(), 'some internal error'),
            ))
            ->willReturn($jsonResponse);

        $this->assertSame($jsonResponse, $this->sut()->par($requestMock));
    }
}
