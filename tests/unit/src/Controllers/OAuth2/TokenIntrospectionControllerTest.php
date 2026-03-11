<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers\OAuth2;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Bridges\OAuth2Bridge;
use SimpleSAML\Module\oidc\Controllers\OAuth2\TokenIntrospectionController;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Exceptions\AuthorizationException;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\RefreshTokenRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\Validators\BearerTokenValidator;
use SimpleSAML\Module\oidc\Services\Api\Authorization;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\AuthenticatedOAuth2ClientResolver;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\Module\oidc\ValueAbstracts\ResolvedClientAuthenticationMethod;
use SimpleSAML\OpenID\Codebooks\ClientAuthenticationMethodsEnum;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

#[CoversClass(TokenIntrospectionController::class)]
class TokenIntrospectionControllerTest extends TestCase
{
    protected MockObject $moduleConfigMock;
    protected MockObject $authenticatedOAuth2ClientResolverMock;
    protected MockObject $routesMock;
    protected MockObject $loggerServiceMock;
    protected MockObject $apiAuthorizationMock;
    protected MockObject $requestParamsResolverMock;
    protected MockObject $bearerTokenValidatorMock;
    protected MockObject $oAuth2BridgeMock;
    protected MockObject $refreshTokenRepositoryMock;

    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getApiEnabled')->willReturn(true);
        $this->moduleConfigMock->method('getApiOAuth2TokenIntrospectionEndpointEnabled')->willReturn(true);

        $this->authenticatedOAuth2ClientResolverMock = $this->createMock(AuthenticatedOAuth2ClientResolver::class);
        $this->routesMock = $this->createMock(Routes::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        $this->apiAuthorizationMock = $this->createMock(Authorization::class);
        $this->requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $this->bearerTokenValidatorMock = $this->createMock(BearerTokenValidator::class);
        $this->oAuth2BridgeMock = $this->createMock(OAuth2Bridge::class);
        $this->refreshTokenRepositoryMock = $this->createMock(RefreshTokenRepository::class);
    }

    protected function sut(
        ?ModuleConfig $moduleConfig = null,
        ?AuthenticatedOAuth2ClientResolver $authenticatedOAuth2ClientResolver = null,
        ?Routes $routes = null,
        ?LoggerService $loggerService = null,
        ?Authorization $apiAuthorization = null,
        ?RequestParamsResolver $requestParamsResolver = null,
        ?BearerTokenValidator $bearerTokenValidator = null,
        ?OAuth2Bridge $oAuth2Bridge = null,
        ?RefreshTokenRepository $refreshTokenRepository = null,
    ): TokenIntrospectionController {
        return new TokenIntrospectionController(
            $moduleConfig ?? $this->moduleConfigMock,
            $authenticatedOAuth2ClientResolver ?? $this->authenticatedOAuth2ClientResolverMock,
            $routes ?? $this->routesMock,
            $loggerService ?? $this->loggerServiceMock,
            $apiAuthorization ?? $this->apiAuthorizationMock,
            $requestParamsResolver ?? $this->requestParamsResolverMock,
            $bearerTokenValidator ?? $this->bearerTokenValidatorMock,
            $oAuth2Bridge ?? $this->oAuth2BridgeMock,
            $refreshTokenRepository ?? $this->refreshTokenRepositoryMock,
        );
    }

    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(TokenIntrospectionController::class, $this->sut());
    }

    public function testConstructThrowsForbiddenIfApiNotEnabled(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getApiEnabled')->willReturn(false);

        $this->expectException(OidcServerException::class);
        try {
            $this->sut();
        } catch (OidcServerException $e) {
            $this->assertSame('API capabilities not enabled.', $e->getHint());
            throw $e;
        }
    }

    public function testConstructThrowsForbiddenIfIntrospectionNotEnabled(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getApiEnabled')->willReturn(true);
        $this->moduleConfigMock->method('getApiOAuth2TokenIntrospectionEndpointEnabled')->willReturn(false);

        $this->expectException(OidcServerException::class);
        try {
            $this->sut();
        } catch (OidcServerException $e) {
            $this->assertSame('OAuth2 Token Introspection API endpoint not enabled.', $e->getHint());
            throw $e;
        }
    }

    private function createValidResolvedClientAuthenticationMethodMock(): MockObject&ResolvedClientAuthenticationMethod
    {
        $mock = $this->createMock(ResolvedClientAuthenticationMethod::class);
        $mock->method('getClientAuthenticationMethod')->willReturn(ClientAuthenticationMethodsEnum::ClientSecretBasic);
        $clientMock = $this->createMock(ClientEntity::class);
        $clientMock->method('getIdentifier')->willReturn('client-id');
        $mock->method('getClient')->willReturn($clientMock);

        return $mock;
    }

    public function testInvokeReturnsUnauthorizedOnAuthorizationException(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn(null);

        $this->apiAuthorizationMock->expects($this->once())
            ->method('requireTokenForAnyOfScope')
            ->willThrowException(new AuthorizationException('Unauthorized client.'));

        $this->loggerServiceMock->expects($this->once())
            ->method('error')
            ->with($this->stringContains('AuthorizationException: Unauthorized client.'));

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonErrorResponse')
            ->with('unauthorized', 'Unauthorized client.', 401)
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }

    public function testInvokeReturnsBadRequestIfMissingToken(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn($this->createValidResolvedClientAuthenticationMethodMock()); // client is authenticated

        $this->requestParamsResolverMock->expects($this->once())
            ->method('getFromRequestBasedOnAllowedMethods')
            ->with('token', $requestMock, [HttpMethodsEnum::POST])
            ->willReturn(null);

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonErrorResponse')
            ->with('invalid_request', 'Missing token parameter.', 400)
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }

    public function testInvokeReturnsActiveFalseIfTokenInvalid(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn($this->createValidResolvedClientAuthenticationMethodMock());

        $this->requestParamsResolverMock
            ->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnMap([
                ['token', $requestMock, [HttpMethodsEnum::POST], 'invalid-token'],
                ['token_type_hint', $requestMock, [HttpMethodsEnum::POST], null],
            ]);

        $this->bearerTokenValidatorMock->expects($this->once())
            ->method('ensureValidAccessToken')
            ->with('invalid-token')
            ->willThrowException(new \Exception('bad token'));

        $this->oAuth2BridgeMock->expects($this->once())
            ->method('decrypt')
            ->with('invalid-token')
            ->willThrowException(new \Exception('bad refresh token'));

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with(['active' => false])
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }

    public function testInvokeCallsAccessTokenFirstRefreshSecondIfNoHint(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn($this->createValidResolvedClientAuthenticationMethodMock());

        $this->requestParamsResolverMock
            ->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnMap([
                ['token', $requestMock, [HttpMethodsEnum::POST], 'invalid-access-token'],
                ['token_type_hint', $requestMock, [HttpMethodsEnum::POST], null],
            ]);

        $this->bearerTokenValidatorMock->expects($this->once())
            ->method('ensureValidAccessToken')
            ->with('invalid-access-token')
            ->willThrowException(new \Exception('bad token'));

        $this->oAuth2BridgeMock->expects($this->once())
            ->method('decrypt')
            ->with('invalid-access-token')
            ->willReturn(json_encode([
                'expire_time' => time() + 3600,
                'refresh_token_id' => 'ref-1',
                'scopes' => ['scope1'],
                'client_id' => 'client1',
            ]));

        $this->refreshTokenRepositoryMock->method('isRefreshTokenRevoked')
            ->with('ref-1')
            ->willReturn(false);

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with($this->callback(function (array $data) {
                return $data['active'] === true && $data['client_id'] === 'client1';
            }))
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }

    public function testInvokeWithTokenTypeHintAccessToken(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn($this->createValidResolvedClientAuthenticationMethodMock());

        $this->requestParamsResolverMock
            ->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnMap([
                ['token', $requestMock, [HttpMethodsEnum::POST], 'valid-access-token'],
                ['token_type_hint', $requestMock, [HttpMethodsEnum::POST], 'access_token'],
            ]);

        $jwsMock = $this->createMock(\SimpleSAML\OpenID\Jws\ParsedJws::class);
        $jwsMock->method('getPayloadClaim')->with('scopes')->willReturn(['scope2']);
        $jwsMock->method('getAudience')->willReturn(['client2']);
        $jwsMock->method('getExpirationTime')->willReturn(1000);

        $this->bearerTokenValidatorMock->expects($this->once())
            ->method('ensureValidAccessToken')
            ->with('valid-access-token')
            ->willReturn($jwsMock);

        $this->oAuth2BridgeMock->expects($this->never())->method('decrypt');

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with($this->callback(function (array $data) {
                return $data['active'] === true && $data['client_id'] === 'client2';
            }))
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }

    public function testInvokeWithTokenTypeHintRefreshToken(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn($this->createValidResolvedClientAuthenticationMethodMock());

        $this->requestParamsResolverMock
            ->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnMap([
                ['token', $requestMock, [HttpMethodsEnum::POST], 'valid-refresh-token'],
                ['token_type_hint', $requestMock, [HttpMethodsEnum::POST], 'refresh_token'],
            ]);

        $this->bearerTokenValidatorMock->expects($this->never())->method('ensureValidAccessToken');

        $this->oAuth2BridgeMock->expects($this->once())
            ->method('decrypt')
            ->with('valid-refresh-token')
            ->willReturn(json_encode([
                'expire_time' => time() + 3600,
                'refresh_token_id' => 'ref-1',
                'scopes' => ['scope1'],
                'client_id' => 'client3',
            ]));

        $this->refreshTokenRepositoryMock->method('isRefreshTokenRevoked')
            ->with('ref-1')
            ->willReturn(false);

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with($this->callback(function (array $data) {
                return $data['active'] === true && $data['client_id'] === 'client3';
            }))
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }

    public function testInvokeReturnsExpectedAccessTokenPayload(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn($this->createValidResolvedClientAuthenticationMethodMock());

        $this->requestParamsResolverMock
            ->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnMap([
                ['token', $requestMock, [HttpMethodsEnum::POST], 'valid-access-token'],
                ['token_type_hint', $requestMock, [HttpMethodsEnum::POST], 'access_token'],
            ]);

        $jwsMock = $this->createMock(\SimpleSAML\OpenID\Jws\ParsedJws::class);
        $jwsMock->method('getPayloadClaim')->with('scopes')->willReturn(['scope1', 'scope2']);
        $jwsMock->method('getExpirationTime')->willReturn(1000);
        $jwsMock->method('getIssuedAt')->willReturn(500);
        $jwsMock->method('getNotBefore')->willReturn(500);
        $jwsMock->method('getSubject')->willReturn('sub1');
        $jwsMock->method('getAudience')->willReturn(['client1']);
        $jwsMock->method('getIssuer')->willReturn('iss1');
        $jwsMock->method('getJwtId')->willReturn('jti1');

        $this->bearerTokenValidatorMock->expects($this->once())
            ->method('ensureValidAccessToken')
            ->with('valid-access-token')
            ->willReturn($jwsMock);

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with([
                'active' => true,
                'scope' => 'scope1 scope2',
                'client_id' => 'client1',
                'token_type' => 'Bearer',
                'exp' => 1000,
                'iat' => 500,
                'nbf' => 500,
                'sub' => 'sub1',
                'aud' => ['client1'],
                'iss' => 'iss1',
                'jti' => 'jti1',
            ])
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }

    public function testInvokeReturnsExpectedRefreshTokenPayload(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn($this->createValidResolvedClientAuthenticationMethodMock());

        $this->requestParamsResolverMock
            ->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnMap([
                ['token', $requestMock, [HttpMethodsEnum::POST], 'valid-refresh-token'],
                ['token_type_hint', $requestMock, [HttpMethodsEnum::POST], 'refresh_token'],
            ]);

        $this->oAuth2BridgeMock->expects($this->once())
            ->method('decrypt')
            ->with('valid-refresh-token')
            ->willReturn(json_encode([
                'expire_time' => time() + 3600,
                'refresh_token_id' => 'jti1',
                'scopes' => ['scope1', 'scope2'],
                'client_id' => 'client1',
                'user_id' => 'sub1',
            ]));

        $this->refreshTokenRepositoryMock->method('isRefreshTokenRevoked')
            ->with('jti1')
            ->willReturn(false);

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with($this->callback(function (array $data) {
                return $data['active'] === true
                    && $data['scope'] === 'scope1 scope2'
                    && $data['client_id'] === 'client1'
                    && $data['exp'] > time()
                    && $data['sub'] === 'sub1'
                    && $data['aud'] === 'client1'
                    && $data['jti'] === 'jti1';
            }))
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }
}
