<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers\OAuth2;

use Exception;
use PDOException;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\Bridges\OAuth2Bridge;
use SimpleSAML\Module\oidc\Controllers\OAuth2\TokenIntrospectionController;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Exceptions\AuthorizationException;
use SimpleSAML\Module\oidc\Exceptions\TokenNotFoundException;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\RefreshTokenRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\Validators\BearerTokenValidator;
use SimpleSAML\Module\oidc\Services\Api\Authorization;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\AuthenticatedOAuth2ClientResolver;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\Module\oidc\ValueAbstracts\ResolvedClientAuthenticationMethod;
use SimpleSAML\OpenID\Codebooks\ClientAuthenticationMethodsEnum;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Exceptions\JwsException;
use SimpleSAML\OpenID\Jws\ParsedJws;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Throwable;

#[CoversClass(TokenIntrospectionController::class)]
#[AllowMockObjectsWithoutExpectations]
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

    protected MockObject $accessTokenRepositoryMock;

    protected MockObject $userRepositoryMock;

    protected MockObject $claimTranslatorExtractorMock;


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
        $this->accessTokenRepositoryMock = $this->createMock(AccessTokenRepository::class);
        $this->userRepositoryMock = $this->createMock(UserRepository::class);
        $this->claimTranslatorExtractorMock = $this->createMock(ClaimTranslatorExtractor::class);
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
        ?AccessTokenRepository $accessTokenRepository = null,
        ?UserRepository $userRepository = null,
        ?ClaimTranslatorExtractor $claimTranslatorExtractor = null,
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
            $accessTokenRepository ?? $this->accessTokenRepositoryMock,
            $userRepository ?? $this->userRepositoryMock,
            $claimTranslatorExtractor ?? $this->claimTranslatorExtractorMock,
        );
    }


    /**
     * The access token's own record, as the repository finds it by the token's 'jti'; issued to the given user,
     * or to no user (a client credentials token, a pre-authorized code with no holder).
     */
    private function givenAccessTokenRecord(string $jti, ?string $userIdentifier = null): void
    {
        $accessTokenEntityMock = $this->createMock(AccessTokenEntity::class);
        $accessTokenEntityMock->method('getUserIdentifier')->willReturn($userIdentifier);

        $this->accessTokenRepositoryMock->method('findById')
            ->with($jti)
            ->willReturn($accessTokenEntityMock);
    }


    private function givenUserRecord(string $userIdentifier, array $claims): void
    {
        $userEntityMock = $this->createMock(UserEntity::class);
        $userEntityMock->method('getClaims')->willReturn($claims);

        $this->userRepositoryMock->method('getUserEntityByIdentifier')
            ->with($userIdentifier)
            ->willReturn($userEntityMock);
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


    /**
     * @param string $clientId Identifier the client authenticated as. A caller is only told about tokens
     * issued to it, so this is what the tokens in these tests have to belong to.
     */
    private function createValidResolvedClientAuthenticationMethodMock(
        string $clientId = 'client-id',
    ): MockObject&ResolvedClientAuthenticationMethod {
        $mock = $this->createMock(ResolvedClientAuthenticationMethod::class);
        $mock->method('getClientAuthenticationMethod')->willReturn(ClientAuthenticationMethodsEnum::ClientSecretBasic);
        $clientMock = $this->createMock(ClientEntity::class);
        $clientMock->method('getIdentifier')->willReturn($clientId);
        $mock->method('getClient')->willReturn($clientMock);

        return $mock;
    }


    public function testInvokeReturnsUnauthorizedOnAuthorizationException(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn(null);

        $this->apiAuthorizationMock->expects($this->once())
            ->method('requireCallerForAnyOfScope')
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


    /**
     * A failure of the OP's own while the caller is being authenticated - the database did not answer - is
     * not a 401, which RFC 7662 section 2.3 has mean invalid credentials, and the API token is not tried
     * instead: the request is answered as the OP's failure, and logged as one.
     */
    public function testInvokeAnswersAFailureWhileAuthenticatingTheCallerAsAServerError(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willThrowException(new RuntimeException('Database error: SQLSTATE[HY000] [2002] Connection refused'));
        $this->apiAuthorizationMock->expects($this->never())->method('requireCallerForAnyOfScope');

        $this->loggerServiceMock->expects($this->once())
            ->method('error')
            ->with(
                $this->stringContains('Connection refused'),
                ['exception' => RuntimeException::class],
            );

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonErrorResponse')
            ->with('server_error', 'Unable to process the introspection request.', 500)
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
            ->willThrowException(new JwsException('bad token'));

        $this->oAuth2BridgeMock->expects($this->once())
            ->method('decrypt')
            ->with('invalid-token')
            ->willThrowException(new Exception('bad refresh token'));

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
            ->willReturn($this->createValidResolvedClientAuthenticationMethodMock('client1'));

        $this->requestParamsResolverMock
            ->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnMap([
                ['token', $requestMock, [HttpMethodsEnum::POST], 'invalid-access-token'],
                ['token_type_hint', $requestMock, [HttpMethodsEnum::POST], null],
            ]);

        $this->bearerTokenValidatorMock->expects($this->once())
            ->method('ensureValidAccessToken')
            ->with('invalid-access-token')
            ->willThrowException(new JwsException('bad token'));

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
            ->with($this->callback(fn(array $data) => $data['active'] === true && $data['client_id'] === 'client1'))
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    public function testInvokeWithTokenTypeHintAccessToken(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn($this->createValidResolvedClientAuthenticationMethodMock('client2'));

        $this->requestParamsResolverMock
            ->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnMap([
                ['token', $requestMock, [HttpMethodsEnum::POST], 'valid-access-token'],
                ['token_type_hint', $requestMock, [HttpMethodsEnum::POST], 'access_token'],
            ]);

        $jwsMock = $this->createMock(ParsedJws::class);
        $jwsMock->method('getPayloadClaim')->with('scopes')->willReturn(['scope2']);
        $jwsMock->method('getAudience')->willReturn(['client2']);
        $jwsMock->method('getExpirationTime')->willReturn(1000);
        $jwsMock->method('getJwtId')->willReturn('jti2');

        $this->bearerTokenValidatorMock->expects($this->once())
            ->method('ensureValidAccessToken')
            ->with('valid-access-token')
            ->willReturn($jwsMock);
        $this->givenAccessTokenRecord('jti2');

        $this->oAuth2BridgeMock->expects($this->never())->method('decrypt');

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with($this->callback(fn(array $data) => $data['active'] === true && $data['client_id'] === 'client2'))
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    public function testInvokeWithTokenTypeHintRefreshToken(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn($this->createValidResolvedClientAuthenticationMethodMock('client3'));

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
            ->with($this->callback(fn(array $data) => $data['active'] === true && $data['client_id'] === 'client3'))
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    /**
     * A subject of "0" is valid (the translation may yield it) and must be reported like any other; only an
     * absent member is left out.
     */
    #[DataProvider('accessTokenSubjectProvider')]
    public function testInvokeReturnsExpectedAccessTokenPayload(string $subject): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn($this->createValidResolvedClientAuthenticationMethodMock('client1'));

        $this->requestParamsResolverMock
            ->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnMap([
                ['token', $requestMock, [HttpMethodsEnum::POST], 'valid-access-token'],
                ['token_type_hint', $requestMock, [HttpMethodsEnum::POST], 'access_token'],
            ]);

        $jwsMock = $this->createMock(ParsedJws::class);
        $jwsMock->method('getPayloadClaim')->with('scopes')->willReturn(['scope1', 'scope2']);
        $jwsMock->method('getExpirationTime')->willReturn(1000);
        $jwsMock->method('getIssuedAt')->willReturn(500);
        $jwsMock->method('getNotBefore')->willReturn(500);
        $jwsMock->method('getSubject')->willReturn($subject);
        $jwsMock->method('getAudience')->willReturn(['client1']);
        $jwsMock->method('getIssuer')->willReturn('iss1');
        $jwsMock->method('getJwtId')->willReturn('jti1');

        $this->bearerTokenValidatorMock->expects($this->once())
            ->method('ensureValidAccessToken')
            ->with('valid-access-token')
            ->willReturn($jwsMock);
        $this->givenAccessTokenRecord('jti1');

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
                'sub' => $subject,
                'aud' => ['client1'],
                'iss' => 'iss1',
                'jti' => 'jti1',
            ])
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    public static function accessTokenSubjectProvider(): array
    {
        return [
            'a subject' => ['sub1'],
            'the falsy but valid subject "0"' => ['0'],
        ];
    }


    /**
     * The subject reported for a refresh token is the one its payload carries as 'sub' -- the subject its
     * access token and ID token were issued with. A payload written before the module recorded it has only
     * the internal 'user_id', which then stands, as it does in that token's access token.
     */
    #[DataProvider('refreshTokenSubjectProvider')]
    public function testInvokeReturnsExpectedRefreshTokenPayload(array $subjectFields, string $expectedSubject): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn($this->createValidResolvedClientAuthenticationMethodMock('client1'));

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
                ...$subjectFields,
            ]));

        $this->refreshTokenRepositoryMock->method('isRefreshTokenRevoked')
            ->with('jti1')
            ->willReturn(false);

        // A refresh token is never shown to a resource server, so no user claims are read for it.
        $this->userRepositoryMock->expects($this->never())->method('getUserEntityByIdentifier');
        $this->claimTranslatorExtractorMock->expects($this->never())->method('extract');

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with($this->callback(fn(array $data) => $data['active'] === true
                && $data['scope'] === 'scope1 scope2'
                && count($data) === 7
                && $data['client_id'] === 'client1'
                && $data['exp'] > time()
                && $data['sub'] === $expectedSubject
                && $data['aud'] === 'client1'
                && $data['jti'] === 'jti1'))
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    public static function refreshTokenSubjectProvider(): array
    {
        return [
            'payload carries the subject' => [['user_id' => 'internal-id', 'sub' => 'sub1'], 'sub1'],
            'payload carries the falsy but valid subject "0"' => [['user_id' => 'internal-id', 'sub' => '0'], '0'],
            'legacy payload without a subject' => [['user_id' => 'sub1'], 'sub1'],
        ];
    }


    public function testInvokeDoesNotTellClientAboutAnotherClientsAccessToken(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn($this->createValidResolvedClientAuthenticationMethodMock('curious-client'));

        $this->requestParamsResolverMock
            ->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnMap([
                ['token', $requestMock, [HttpMethodsEnum::POST], 'another-clients-access-token'],
                ['token_type_hint', $requestMock, [HttpMethodsEnum::POST], 'access_token'],
            ]);

        // A perfectly valid token, only not this caller's.
        $jwsMock = $this->createMock(ParsedJws::class);
        $jwsMock->method('getPayloadClaim')->with('scopes')->willReturn(['openid', 'profile']);
        $jwsMock->method('getAudience')->willReturn(['other-client']);
        $jwsMock->method('getSubject')->willReturn('someones-subject-identifier');
        $jwsMock->method('getExpirationTime')->willReturn(time() + 3600);

        $this->bearerTokenValidatorMock->expects($this->once())
            ->method('ensureValidAccessToken')
            ->with('another-clients-access-token')
            ->willReturn($jwsMock);
        // Refused before anything is read about the token's user.
        $this->accessTokenRepositoryMock->expects($this->never())->method('findById');
        $this->userRepositoryMock->expects($this->never())->method('getUserEntityByIdentifier');

        $responseMock = $this->createMock(JsonResponse::class);
        // Nothing about the token comes back, not even that it exists.
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with(['active' => false])
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    /**
     * A refresh token the repository has no record of (its user was deleted, and the deletion cascaded to it) is
     * inactive, not an error.
     */
    public function testInvokeAnswersARefreshTokenWithoutARecordAsInactive(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn($this->createValidResolvedClientAuthenticationMethodMock('client1'));

        $this->requestParamsResolverMock
            ->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnMap([
                ['token', $requestMock, [HttpMethodsEnum::POST], 'orphaned-refresh-token'],
                ['token_type_hint', $requestMock, [HttpMethodsEnum::POST], 'refresh_token'],
            ]);

        $this->oAuth2BridgeMock->expects($this->once())
            ->method('decrypt')
            ->with('orphaned-refresh-token')
            ->willReturn(json_encode([
                'expire_time' => time() + 3600,
                'refresh_token_id' => 'ref-gone',
                'scopes' => ['openid'],
                'client_id' => 'client1',
            ]));

        $this->refreshTokenRepositoryMock->method('isRefreshTokenRevoked')
            ->with('ref-gone')
            ->willThrowException(new TokenNotFoundException('RefreshToken not found: ref-gone'));

        $this->loggerServiceMock->expects($this->once())
            ->method('error')
            ->with($this->stringContains('Refresh token has no record'));

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with(['active' => false])
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    public function testInvokeDoesNotTellClientAboutAnotherClientsRefreshToken(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn($this->createValidResolvedClientAuthenticationMethodMock('curious-client'));

        $this->requestParamsResolverMock
            ->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnMap([
                ['token', $requestMock, [HttpMethodsEnum::POST], 'another-clients-refresh-token'],
                ['token_type_hint', $requestMock, [HttpMethodsEnum::POST], 'refresh_token'],
            ]);

        $this->oAuth2BridgeMock->expects($this->once())
            ->method('decrypt')
            ->with('another-clients-refresh-token')
            ->willReturn(json_encode([
                'expire_time' => time() + 3600,
                'refresh_token_id' => 'ref-1',
                'scopes' => ['openid'],
                'client_id' => 'other-client',
                'user_id' => 'someones-subject-identifier',
            ]));

        $this->refreshTokenRepositoryMock->method('isRefreshTokenRevoked')
            ->with('ref-1')
            ->willReturn(false);

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with(['active' => false])
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    /**
     * A token whose owner the payload does not state can not be matched against the caller, so the caller
     * is told nothing rather than being given the benefit of the doubt.
     */
    public function testInvokeDoesNotTellClientAboutTokenWithoutEstablishedOwner(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn($this->createValidResolvedClientAuthenticationMethodMock('client-id'));

        $this->requestParamsResolverMock
            ->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnMap([
                ['token', $requestMock, [HttpMethodsEnum::POST], 'audienceless-access-token'],
                ['token_type_hint', $requestMock, [HttpMethodsEnum::POST], 'access_token'],
            ]);

        $jwsMock = $this->createMock(ParsedJws::class);
        $jwsMock->method('getPayloadClaim')->with('scopes')->willReturn(['openid']);
        $jwsMock->method('getAudience')->willReturn([]);
        $jwsMock->method('getExpirationTime')->willReturn(time() + 3600);

        $this->bearerTokenValidatorMock->expects($this->once())
            ->method('ensureValidAccessToken')
            ->with('audienceless-access-token')
            ->willReturn($jwsMock);

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with(['active' => false])
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    /**
     * An identifier PHP considers falsy is still an identifier - a client entity rejects only an empty
     * one - so the client it names is still to be told about its own tokens. The introspection response
     * has its empty values dropped, so the owner has to be established before that happens.
     */
    public function testInvokeLetsClientWithFalsyIdentifierIntrospectItsOwnToken(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn($this->createValidResolvedClientAuthenticationMethodMock('0'));

        $this->requestParamsResolverMock
            ->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnMap([
                ['token', $requestMock, [HttpMethodsEnum::POST], 'own-access-token'],
                ['token_type_hint', $requestMock, [HttpMethodsEnum::POST], 'access_token'],
            ]);

        $jwsMock = $this->createMock(ParsedJws::class);
        $jwsMock->method('getPayloadClaim')->with('scopes')->willReturn(['openid']);
        $jwsMock->method('getAudience')->willReturn(['0']);
        $jwsMock->method('getSubject')->willReturn('own-subject-identifier');
        $jwsMock->method('getExpirationTime')->willReturn(1000);
        $jwsMock->method('getJwtId')->willReturn('own-jti');

        $this->bearerTokenValidatorMock->expects($this->once())
            ->method('ensureValidAccessToken')
            ->with('own-access-token')
            ->willReturn($jwsMock);
        $this->givenAccessTokenRecord('own-jti');

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with(
                $this->callback(
                    fn(array $data) => $data['active'] === true && $data['sub'] === 'own-subject-identifier',
                ),
            )
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    public function testInvokeLetsConfiguredResourceServerIntrospectAnotherClientsToken(): void
    {
        $this->moduleConfigMock->method('getApiOAuth2TokenIntrospectionResourceServerClientIds')
            ->willReturn(['resource-server']);

        $requestMock = $this->createMock(Request::class);
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn($this->createValidResolvedClientAuthenticationMethodMock('resource-server'));

        $this->requestParamsResolverMock
            ->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnMap([
                ['token', $requestMock, [HttpMethodsEnum::POST], 'access-token-of-a-client-it-serves'],
                ['token_type_hint', $requestMock, [HttpMethodsEnum::POST], 'access_token'],
            ]);

        $jwsMock = $this->createMock(ParsedJws::class);
        $jwsMock->method('getPayloadClaim')->with('scopes')->willReturn(['openid']);
        $jwsMock->method('getAudience')->willReturn(['other-client']);
        $jwsMock->method('getExpirationTime')->willReturn(1000);
        $jwsMock->method('getJwtId')->willReturn('served-jti');

        $this->bearerTokenValidatorMock->expects($this->once())
            ->method('ensureValidAccessToken')
            ->with('access-token-of-a-client-it-serves')
            ->willReturn($jwsMock);
        $this->givenAccessTokenRecord('served-jti');

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with(
                $this->callback(
                    fn(array $data) => $data['active'] === true && $data['client_id'] === 'other-client',
                ),
            )
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    /**
     * An API token (named, or known by its fingerprint) and an administrator's session alike.
     */
    #[DataProvider('administrativePrincipalProvider')]
    public function testInvokeLetsApiTokenCallerIntrospectAnyClientsToken(string $principal): void
    {
        $requestMock = $this->createMock(Request::class);
        // No client authentication, so the API token path is taken, and it is not tied to a single client.
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn(null);

        // Named by the principal the API authorization resolved, which is what the log says asked.
        $this->apiAuthorizationMock->expects($this->once())
            ->method('requireCallerForAnyOfScope')
            ->willReturn($principal);
        $debugMessages = [];
        $this->loggerServiceMock->method('debug')
            ->willReturnCallback(function (string $message) use (&$debugMessages): void {
                $debugMessages[] = $message;
            });

        $this->requestParamsResolverMock
            ->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnMap([
                ['token', $requestMock, [HttpMethodsEnum::POST], 'some-clients-access-token'],
                ['token_type_hint', $requestMock, [HttpMethodsEnum::POST], 'access_token'],
            ]);

        $jwsMock = $this->createMock(ParsedJws::class);
        $jwsMock->method('getPayloadClaim')->with('scopes')->willReturn(['openid']);
        $jwsMock->method('getAudience')->willReturn(['some-client']);
        $jwsMock->method('getExpirationTime')->willReturn(1000);
        $jwsMock->method('getJwtId')->willReturn('some-jti');

        $this->bearerTokenValidatorMock->expects($this->once())
            ->method('ensureValidAccessToken')
            ->with('some-clients-access-token')
            ->willReturn($jwsMock);
        $this->givenAccessTokenRecord('some-jti');

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with($this->callback(fn(array $data) => $data['active'] === true && $data['client_id'] === 'some-client'))
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
        $this->assertContains(sprintf('API client %s authenticated.', $principal), $debugMessages);
    }


    public static function administrativePrincipalProvider(): array
    {
        return [
            'a named API token' => ['HR system'],
            'an unnamed API token' => ['token:0123456789abcdef'],
            'an administrator' => [Authorization::ADMIN_PRINCIPAL],
        ];
    }


    /**
     * No key to fingerprint an unnamed API token with is the deployment's configuration error, not a verdict
     * on the caller's credentials: a server error, not a 401.
     */
    public function testInvokeAnswersAnApiCallerWhoCanNotBeNamedAsAServerError(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn(null);
        $this->apiAuthorizationMock->method('requireCallerForAnyOfScope')
            ->willThrowException(new ConfigurationError('Unable to derive the API token fingerprint key'));
        $this->bearerTokenValidatorMock->expects($this->never())->method('ensureValidAccessToken');

        $this->loggerServiceMock->expects($this->once())
            ->method('error')
            ->with(
                $this->stringContains('Unable to derive the API token fingerprint key'),
                ['exception' => ConfigurationError::class],
            );

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonErrorResponse')
            ->with('server_error', 'Unable to process the introspection request.', 500)
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    /**
     * The hub's privilege covers refresh tokens as much as access tokens: the owner test is the role's, not
     * the token type's.
     */
    public function testInvokeLetsTheUpstreamHubIntrospectAnotherClientsRefreshToken(): void
    {
        $this->moduleConfigMock->method('getApiOAuth2TokenIntrospectionUpstreamHubClientIds')
            ->willReturn(['hub']);

        $requestMock = $this->createMock(Request::class);
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn($this->createValidResolvedClientAuthenticationMethodMock('hub'));

        $this->requestParamsResolverMock
            ->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnMap([
                ['token', $requestMock, [HttpMethodsEnum::POST], 'another-clients-refresh-token'],
                ['token_type_hint', $requestMock, [HttpMethodsEnum::POST], 'refresh_token'],
            ]);

        $this->oAuth2BridgeMock->expects($this->once())
            ->method('decrypt')
            ->with('another-clients-refresh-token')
            ->willReturn(json_encode([
                'expire_time' => time() + 3600,
                'refresh_token_id' => 'ref-1',
                'scopes' => ['openid'],
                'client_id' => 'other-client',
                'sub' => 'the-subject',
            ]));

        $this->refreshTokenRepositoryMock->method('isRefreshTokenRevoked')
            ->with('ref-1')
            ->willReturn(false);

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with(
                $this->callback(
                    fn(array $data) => $data['active'] === true && $data['client_id'] === 'other-client',
                ),
            )
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    /**
     * The upstream hub introspects tokens it did not receive itself, which is its whole function, so it is
     * told about any token this OP issued, as a resource server is.
     */
    public function testInvokeLetsTheUpstreamHubIntrospectAnotherClientsToken(): void
    {
        $this->moduleConfigMock->method('getApiOAuth2TokenIntrospectionUpstreamHubClientIds')
            ->willReturn(['hub']);
        $this->moduleConfigMock->expects($this->never())
            ->method('getApiOAuth2TokenIntrospectionResourceServerClientIds');

        $requestMock = $this->createMock(Request::class);
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn($this->createValidResolvedClientAuthenticationMethodMock('hub'));

        $this->requestParamsResolverMock
            ->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnMap([
                ['token', $requestMock, [HttpMethodsEnum::POST], 'access-token-of-a-client-of-this-op'],
                ['token_type_hint', $requestMock, [HttpMethodsEnum::POST], 'access_token'],
            ]);

        $jwsMock = $this->createMock(ParsedJws::class);
        $jwsMock->method('getPayloadClaim')->with('scopes')->willReturn(['openid']);
        $jwsMock->method('getAudience')->willReturn(['other-client']);
        $jwsMock->method('getExpirationTime')->willReturn(1000);
        $jwsMock->method('getJwtId')->willReturn('hub-jti');

        $this->bearerTokenValidatorMock->expects($this->once())
            ->method('ensureValidAccessToken')
            ->with('access-token-of-a-client-of-this-op')
            ->willReturn($jwsMock);
        $this->givenAccessTokenRecord('hub-jti');

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with(
                $this->callback(
                    fn(array $data) => $data['active'] === true && $data['client_id'] === 'other-client',
                ),
            )
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    /**
     * A client named in both roles is the deployment's configuration error, not a verdict on the caller: the
     * request is answered as the OP's failure, before any token is looked at, rather than by letting one of
     * the two roles win.
     */
    public function testInvokeAnswersAClientNamedInBothRolesAsAServerError(): void
    {
        $this->moduleConfigMock->method('getApiOAuth2TokenIntrospectionUpstreamHubClientIds')
            ->willThrowException(new ConfigurationError('Client(s) hub are named both in …'));

        $requestMock = $this->createMock(Request::class);
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn($this->createValidResolvedClientAuthenticationMethodMock('hub'));
        $this->bearerTokenValidatorMock->expects($this->never())->method('ensureValidAccessToken');

        $this->loggerServiceMock->expects($this->once())
            ->method('error')
            ->with(
                $this->stringContains('named both in'),
                ['exception' => ConfigurationError::class],
            );

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonErrorResponse')
            ->with('server_error', 'Unable to process the introspection request.', 500)
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    /**
     * @param ?string $type The token's 'typ' header; null for a token minted before the module wrote one.
     */
    private function givenIntrospectableAccessToken(
        MockObject $requestMock,
        string $jti,
        array $scopes,
        string $subject = 'token-subject',
        ?string $type = 'at+jwt',
        ?string $tokenTypeHint = 'access_token',
    ): void {
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn($this->createValidResolvedClientAuthenticationMethodMock('client1'));

        $this->requestParamsResolverMock
            ->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnMap([
                ['token', $requestMock, [HttpMethodsEnum::POST], 'valid-access-token'],
                ['token_type_hint', $requestMock, [HttpMethodsEnum::POST], $tokenTypeHint],
            ]);

        $jwsMock = $this->createMock(ParsedJws::class);
        $jwsMock->method('getType')->willReturn($type);
        $jwsMock->method('getPayloadClaim')->with('scopes')->willReturn($scopes);
        $jwsMock->method('getExpirationTime')->willReturn(1000);
        $jwsMock->method('getIssuedAt')->willReturn(500);
        $jwsMock->method('getSubject')->willReturn($subject);
        $jwsMock->method('getAudience')->willReturn(['client1']);
        $jwsMock->method('getIssuer')->willReturn('iss1');
        $jwsMock->method('getJwtId')->willReturn($jti);

        $this->bearerTokenValidatorMock->expects($this->once())
            ->method('ensureValidAccessToken')
            ->with('valid-access-token')
            ->willReturn($jwsMock);
    }


    /**
     * The user claims the token's scopes release come from the user record as it is now, after the token's own
     * members; the subject stays the one the token was minted with, not the one the record resolves to today.
     */
    public function testInvokeAddsTheUserClaimsTheTokenScopesReleaseToTheAccessTokenPayload(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->givenIntrospectableAccessToken($requestMock, 'jti1', ['openid', 'profile']);
        $this->givenAccessTokenRecord('jti1', 'user1');
        $this->givenUserRecord('user1', ['uid' => ['user1'], 'displayName' => ['Ada']]);

        // A translation can name anything, so the released set also carries names the token members use; none of
        // them displaces the token's own.
        $this->claimTranslatorExtractorMock->expects($this->once())
            ->method('extract')
            ->with(['openid', 'profile'], ['uid' => ['user1'], 'displayName' => ['Ada']])
            ->willReturn([
                'sub' => 'subject-as-resolved-now',
                'voperson_id' => 'ada@example.org',
                'name' => 'Ada',
                'active' => false,
                'client_id' => 'another-client',
                'exp' => 1,
                'aud' => ['another-client'],
            ]);

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with([
                'active' => true,
                'scope' => 'openid profile',
                'client_id' => 'client1',
                'token_type' => 'Bearer',
                'exp' => 1000,
                'iat' => 500,
                'sub' => 'token-subject',
                'aud' => ['client1'],
                'iss' => 'iss1',
                'jti' => 'jti1',
                'voperson_id' => 'ada@example.org',
                'name' => 'Ada',
            ])
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    /**
     * Only an absent scope value is dropped: "0" is a scope-token (RFC 6749 section 3.3) and is kept, in the
     * 'scope' member and in the scopes the user claims are released for.
     */
    public function testInvokeKeepsAScopeNamedZero(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->givenIntrospectableAccessToken($requestMock, 'jti1', ['openid', '0', '', 42]);
        $this->givenAccessTokenRecord('jti1', 'user1');
        $this->givenUserRecord('user1', []);

        $this->claimTranslatorExtractorMock->expects($this->once())
            ->method('extract')
            ->with(['openid', '0'], [])
            ->willReturn([]);

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with($this->callback(fn(array $data) => $data['active'] === true && $data['scope'] === 'openid 0'))
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    public function testInvokeAnswersATokenIssuedWithoutAUserWithTokenMembersOnly(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->givenIntrospectableAccessToken($requestMock, 'jti1', ['vci-credential'], 'client1');
        $this->givenAccessTokenRecord('jti1', null);

        $this->userRepositoryMock->expects($this->never())->method('getUserEntityByIdentifier');
        $this->claimTranslatorExtractorMock->expects($this->never())->method('extract');

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with([
                'active' => true,
                'scope' => 'vci-credential',
                'client_id' => 'client1',
                'token_type' => 'Bearer',
                'exp' => 1000,
                'iat' => 500,
                'sub' => 'client1',
                'aud' => ['client1'],
                'iss' => 'iss1',
                'jti' => 'jti1',
            ])
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    /**
     * Deleting a user deletes the tokens issued to them; a cached copy of the token's record may still answer
     * for it, and then the missing user record is what tells that the token was revoked with the user.
     */
    public function testInvokeAnswersATokenWhoseUserRecordIsGoneAsInactive(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->givenIntrospectableAccessToken($requestMock, 'jti1', ['openid']);
        $this->givenAccessTokenRecord('jti1', 'deleted-user');

        $this->userRepositoryMock->expects($this->once())
            ->method('getUserEntityByIdentifier')
            ->with('deleted-user')
            ->willReturn(null);
        $this->claimTranslatorExtractorMock->expects($this->never())->method('extract');

        $this->loggerServiceMock->expects($this->once())
            ->method('warning')
            ->with($this->stringContains('whose record is gone'));

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with(['active' => false])
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    public function testInvokeAnswersATokenWhoseOwnRecordIsGoneAsInactive(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->givenIntrospectableAccessToken($requestMock, 'jti1', ['openid']);

        $this->accessTokenRepositoryMock->expects($this->once())
            ->method('findById')
            ->with('jti1')
            ->willReturn(null);
        $this->userRepositoryMock->expects($this->never())->method('getUserEntityByIdentifier');

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with(['active' => false])
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    /**
     * The OP failing to read the user record is no verdict on the token: not 'active: false', which a resource
     * server would act on and may cache, but the OP's own error.
     */
    public function testInvokeAnswersAFailureWhileReadingTheUserRecordAsAServerError(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->givenIntrospectableAccessToken($requestMock, 'jti1', ['openid']);
        $this->givenAccessTokenRecord('jti1', 'user1');

        $this->userRepositoryMock->expects($this->once())
            ->method('getUserEntityByIdentifier')
            ->willThrowException(new RuntimeException('Database error: SQLSTATE[HY000] [2002] Connection refused'));

        $this->loggerServiceMock->expects($this->once())
            ->method('error')
            ->with(
                $this->stringContains('Connection refused'),
                ['exception' => RuntimeException::class],
            );
        $this->routesMock->expects($this->never())->method('newJsonResponse');

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonErrorResponse')
            ->with('server_error', 'Unable to process the introspection request.', 500)
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    /**
     * Without a token_type_hint the access token path is tried first; the user claims are released as with one.
     */
    public function testInvokeAddsTheUserClaimsWithoutATokenTypeHint(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->givenIntrospectableAccessToken($requestMock, 'jti1', ['openid'], tokenTypeHint: null);
        $this->givenAccessTokenRecord('jti1', 'user1');
        $this->givenUserRecord('user1', ['uid' => ['user1']]);

        $this->claimTranslatorExtractorMock->expects($this->once())
            ->method('extract')
            ->with(['openid'], ['uid' => ['user1']])
            ->willReturn(['sub' => 'user1', 'voperson_id' => 'user1@example.org']);
        $this->oAuth2BridgeMock->expects($this->never())->method('decrypt');

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with($this->callback(fn(array $data) => $data['active'] === true
                && $data['sub'] === 'token-subject'
                && $data['voperson_id'] === 'user1@example.org'))
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    /**
     * A token minted before the module wrote a 'typ' header carries the internal user identifier as 'sub'; as at
     * the UserInfo endpoint, the 'sub' the 'openid' scope releases from the current record stands for it.
     */
    public function testInvokeReportsTheReleasedSubjectForALegacyAccessToken(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->givenIntrospectableAccessToken($requestMock, 'jti1', ['openid'], 'internal-user-id', null);
        $this->givenAccessTokenRecord('jti1', 'internal-user-id');
        $this->givenUserRecord('internal-user-id', ['uid' => ['internal-user-id']]);

        $this->claimTranslatorExtractorMock->expects($this->once())
            ->method('extract')
            ->willReturn(['sub' => 'resolved-subject']);

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with($this->callback(fn(array $data) => $data['active'] === true
                && $data['sub'] === 'resolved-subject'
                && $data['jti'] === 'jti1'))
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    /**
     * A legacy token whose record names no user keeps its own 'sub' (nothing is released to replace it with).
     */
    public function testInvokeKeepsTheTokenSubjectForALegacyAccessTokenWithoutAUser(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->givenIntrospectableAccessToken($requestMock, 'jti1', ['openid'], 'internal-user-id', null);
        $this->givenAccessTokenRecord('jti1', null);

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with($this->callback(fn(array $data) => $data['active'] === true && $data['sub'] === 'internal-user-id'))
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    /**
     * The validator answering that it has no record of the token is a verdict (the token does not exist here);
     * its database layer failing to answer is not, and is the OP's error.
     */
    public function testInvokeAnswersATokenTheValidatorHasNoRecordOfAsInactive(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn($this->createValidResolvedClientAuthenticationMethodMock());

        $this->requestParamsResolverMock
            ->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnMap([
                ['token', $requestMock, [HttpMethodsEnum::POST], 'unknown-access-token'],
                ['token_type_hint', $requestMock, [HttpMethodsEnum::POST], 'access_token'],
            ]);

        $this->bearerTokenValidatorMock->expects($this->once())
            ->method('ensureValidAccessToken')
            ->willThrowException(new TokenNotFoundException('AccessToken not found: jti-unknown'));

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with(['active' => false])
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    public function testInvokeAnswersAFailureWhileValidatingTheTokenAsAServerError(): void
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

        // What SimpleSAMLphp's Database throws when the revocation lookup can not run.
        $this->bearerTokenValidatorMock->expects($this->once())
            ->method('ensureValidAccessToken')
            ->willThrowException(new Exception('Database error: SQLSTATE[HY000] [2002] Connection refused'));

        $this->loggerServiceMock->expects($this->once())
            ->method('error')
            ->with($this->stringContains('Connection refused'), ['exception' => Exception::class]);
        $this->routesMock->expects($this->never())->method('newJsonResponse');

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonErrorResponse')
            ->with('server_error', 'Unable to process the introspection request.', 500)
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    /**
     * A PDOException thrown while the token's record is fetched is a RuntimeException as well, and a failed read
     * all the same: not the repository's "no record" answer, so not an inactive token.
     */
    public function testInvokeAnswersAFetchFailureWhileValidatingTheTokenAsAServerError(): void
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

        $this->bearerTokenValidatorMock->expects($this->once())
            ->method('ensureValidAccessToken')
            ->willThrowException(new PDOException('SQLSTATE[HY000]: General error: 2013 Lost connection'));
        $this->routesMock->expects($this->never())->method('newJsonResponse');

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonErrorResponse')
            ->with('server_error', 'Unable to process the introspection request.', 500)
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    #[DataProvider('refreshTokenReadFailureProvider')]
    public function testInvokeAnswersAFailureWhileReadingTheRefreshTokenRecordAsAServerError(
        Throwable $readFailure,
    ): void {
        $requestMock = $this->createMock(Request::class);
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn($this->createValidResolvedClientAuthenticationMethodMock('client1'));

        $this->requestParamsResolverMock
            ->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnMap([
                ['token', $requestMock, [HttpMethodsEnum::POST], 'valid-refresh-token'],
                ['token_type_hint', $requestMock, [HttpMethodsEnum::POST], 'refresh_token'],
            ]);

        $this->oAuth2BridgeMock->expects($this->once())
            ->method('decrypt')
            ->willReturn(json_encode([
                'expire_time' => time() + 3600,
                'refresh_token_id' => 'ref-1',
                'scopes' => ['openid'],
                'client_id' => 'client1',
            ]));

        $this->refreshTokenRepositoryMock->method('isRefreshTokenRevoked')
            ->with('ref-1')
            ->willThrowException($readFailure);
        $this->routesMock->expects($this->never())->method('newJsonResponse');

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonErrorResponse')
            ->with('server_error', 'Unable to process the introspection request.', 500)
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    public static function refreshTokenReadFailureProvider(): array
    {
        return [
            'the database did not answer' => [
                new Exception('Database error: SQLSTATE[HY000] [2002] Connection refused'),
            ],
            'the fetch failed' => [new PDOException('SQLSTATE[HY000]: General error: 2013 Lost connection')],
            'the record is corrupt' => [OidcServerException::serverError('Invalid Refresh Token state')],
        ];
    }
}
