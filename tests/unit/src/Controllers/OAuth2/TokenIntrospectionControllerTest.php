<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers\OAuth2;

use Closure;
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
use SimpleSAML\Module\oidc\Codebooks\IntrospectionCallerRoleEnum;
use SimpleSAML\Module\oidc\Controllers\OAuth2\TokenIntrospectionController;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\ClaimSetEntity;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Exceptions\AuthorizationException;
use SimpleSAML\Module\oidc\Exceptions\TokenNotFoundException;
use SimpleSAML\Module\oidc\Exceptions\UpstreamIntrospectionException;
use SimpleSAML\Module\oidc\Factories\Entities\ClaimSetEntityFactory;
use SimpleSAML\Module\oidc\Factories\IntrospectionReleasePolicyFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\RefreshTokenRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\Validators\BearerTokenValidator;
use SimpleSAML\Module\oidc\Services\Api\Authorization;
use SimpleSAML\Module\oidc\Services\Introspection\IntrospectionReleasePolicyInterface;
use SimpleSAML\Module\oidc\Services\Introspection\PassthroughIntrospectionReleasePolicy;
use SimpleSAML\Module\oidc\Services\Introspection\ProxiedTokenIntrospector;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\AuthenticatedOAuth2ClientResolver;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\Module\oidc\ValueAbstracts\IntrospectedTokenOrigin;
use SimpleSAML\Module\oidc\ValueAbstracts\IntrospectionAuthorization;
use SimpleSAML\Module\oidc\ValueAbstracts\IntrospectionReleaseDecision;
use SimpleSAML\Module\oidc\ValueAbstracts\ResolvedClientAuthenticationMethod;
use SimpleSAML\OpenID\Codebooks\ClientAuthenticationMethodsEnum;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Exceptions\JwsException;
use SimpleSAML\OpenID\Jws;
use SimpleSAML\OpenID\Jws\ParsedJws;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Throwable;

#[CoversClass(TokenIntrospectionController::class)]
#[AllowMockObjectsWithoutExpectations]
class TokenIntrospectionControllerTest extends TestCase
{
    protected const string ISSUER = 'https://op.example.org';

    /**
     * Shaped as a compact JWS naming this OP as its issuer, so that it is looked up as an access token of this OP;
     * whether it is one is the (mocked) validator's to say.
     */
    protected const string ACCESS_TOKEN = 'eyJhbGciOiJSUzI1NiIsInR5cCI6ImF0K2p3dCJ9.' .
    'eyJpc3MiOiJodHRwczovL29wLmV4YW1wbGUub3JnIiwianRpIjoianRpMSJ9.c2lnbmF0dXJl';

    /**
     * A compact JWS naming https://node-a.example.org as its issuer: a token this OP did not issue.
     */
    protected const string FOREIGN_ACCESS_TOKEN = 'eyJhbGciOiJSUzI1NiIsInR5cCI6ImF0K2p3dCJ9.' .
    'eyJpc3MiOiJodHRwczovL25vZGUtYS5leGFtcGxlLm9yZyIsImp0aSI6ImZvcmVpZ24xIn0.c2lnbmF0dXJl';

    /**
     * A compact JWS naming no issuer.
     */
    protected const string ISSUERLESS_JWS = 'eyJhbGciOiJSUzI1NiJ9.eyJqdGkiOiJqdGkxIn0.c2lnbmF0dXJl';


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

    protected MockObject $introspectionReleasePolicyFactoryMock;

    protected MockObject $proxiedTokenIntrospectorMock;


    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getApiEnabled')->willReturn(true);
        $this->moduleConfigMock->method('getApiOAuth2TokenIntrospectionEndpointEnabled')->willReturn(true);
        $this->moduleConfigMock->method('getIssuer')->willReturn(self::ISSUER);

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

        // The default: no policy configured, so every entitled caller is told the whole answer.
        $this->introspectionReleasePolicyFactoryMock = $this->createMock(IntrospectionReleasePolicyFactory::class);
        $this->introspectionReleasePolicyFactoryMock->method('build')
            ->willReturn(new PassthroughIntrospectionReleasePolicy());

        $this->proxiedTokenIntrospectorMock = $this->createMock(ProxiedTokenIntrospector::class);
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
        ?IntrospectionReleasePolicyFactory $introspectionReleasePolicyFactory = null,
        ?ProxiedTokenIntrospector $proxiedTokenIntrospector = null,
        ?Jws $jws = null,
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
            $introspectionReleasePolicyFactory ?? $this->introspectionReleasePolicyFactoryMock,
            $proxiedTokenIntrospector ?? $this->proxiedTokenIntrospectorMock,
            // The library's own parser, which routes a presented token by its shape and its issuer.
            $jws ?? new Jws(),
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


    /**
     * The 'openid' scope releases 'sub', and the user record resolves it to the given subject; what a token minted
     * before the module wrote 'typ' is reported with.
     */
    private function givenTheResolvedSubject(string $subject): void
    {
        $this->claimTranslatorExtractorMock->method('getClaimSet')
            ->willReturnCallback(fn(string $scope): ?ClaimSetEntity =>
                $scope === 'openid' ? new ClaimSetEntity('openid', ['sub']) : null);
        $this->claimTranslatorExtractorMock->method('extractSubject')->willReturn($subject);
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


    /**
     * A value which is not a JWS can only be a refresh token of this OP, and is looked up as one only.
     */
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

        $this->bearerTokenValidatorMock->expects($this->never())->method('ensureValidAccessToken');
        $this->proxiedTokenIntrospectorMock->expects($this->never())->method('introspect');

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


    /**
     * RFC 7662 section 2.1: a hint is an optimisation, which the authorization server "MAY ignore ... particularly
     * if it is able to detect the token type automatically". A refresh token of this OP is never a JWS, so it is
     * found as one whatever the hint names, a wrong or an unknown value included.
     */
    #[DataProvider('anyTokenTypeHintProvider')]
    public function testInvokeLooksAValueWhichIsNotAJwsUpAsARefreshTokenWhateverTheHint(?string $hint): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn($this->createValidResolvedClientAuthenticationMethodMock('client1'));

        $this->requestParamsResolverMock
            ->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnMap([
                ['token', $requestMock, [HttpMethodsEnum::POST], 'valid-refresh-token'],
                ['token_type_hint', $requestMock, [HttpMethodsEnum::POST], $hint],
            ]);

        $this->bearerTokenValidatorMock->expects($this->never())->method('ensureValidAccessToken');
        $this->proxiedTokenIntrospectorMock->expects($this->never())->method('introspect');

        $this->oAuth2BridgeMock->expects($this->once())
            ->method('decrypt')
            ->with('valid-refresh-token')
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


    public static function anyTokenTypeHintProvider(): array
    {
        return [
            'no hint' => [null],
            'access_token' => ['access_token'],
            'refresh_token' => ['refresh_token'],
            'an unknown value' => ['id_token'],
        ];
    }


    /**
     * An access token is a JWS, found as one whatever the hint names; a JWS is never looked up as a refresh token.
     */
    #[DataProvider('anyTokenTypeHintProvider')]
    public function testInvokeLooksAJwsNamingThisOpUpAsAnAccessTokenWhateverTheHint(?string $hint): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->givenIntrospectableAccessToken($requestMock, 'jti1', ['openid'], tokenTypeHint: $hint);
        $this->givenAccessTokenRecord('jti1');

        $this->oAuth2BridgeMock->expects($this->never())->method('decrypt');
        $this->proxiedTokenIntrospectorMock->expects($this->never())->method('introspect');

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with($this->callback(fn(array $data): bool => $data['active'] === true && $data['jti'] === 'jti1'))
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    /**
     * A JWS naming no issuer does not claim to be anyone else's either: it is validated here, which refuses it.
     */
    public function testInvokeValidatesAJwsNamingNoIssuerHere(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn($this->createValidResolvedClientAuthenticationMethodMock('client1'));

        $this->requestParamsResolverMock
            ->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnMap([
                ['token', $requestMock, [HttpMethodsEnum::POST], self::ISSUERLESS_JWS],
                ['token_type_hint', $requestMock, [HttpMethodsEnum::POST], null],
            ]);

        $this->bearerTokenValidatorMock->expects($this->once())
            ->method('ensureValidAccessToken')
            ->with(self::ISSUERLESS_JWS)
            ->willThrowException(new JwsException('bad token'));
        $this->oAuth2BridgeMock->expects($this->never())->method('decrypt');
        $this->proxiedTokenIntrospectorMock->expects($this->never())->method('introspect');

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with(['active' => false])
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    /**
     * A JWS naming another issuer is a token this OP did not issue. It is asked about upstream with the caller and
     * the hint as they came, never validated here, and the answer is the proxied introspector's.
     */
    public function testInvokeAsksAboutATokenOfAnotherIssuerUpstream(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn($this->createValidResolvedClientAuthenticationMethodMock('rs1'));
        $this->moduleConfigMock->method('getApiOAuth2TokenIntrospectionResourceServerClientIds')->willReturn(['rs1']);

        $this->requestParamsResolverMock
            ->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnMap([
                ['token', $requestMock, [HttpMethodsEnum::POST], self::FOREIGN_ACCESS_TOKEN],
                ['token_type_hint', $requestMock, [HttpMethodsEnum::POST], 'refresh_token'],
            ]);

        $this->bearerTokenValidatorMock->expects($this->never())->method('ensureValidAccessToken');
        $this->oAuth2BridgeMock->expects($this->never())->method('decrypt');

        $answer = ['active' => true, 'iss' => 'https://node-a.example.org', 'sub' => 'someone'];
        $this->proxiedTokenIntrospectorMock->expects($this->once())
            ->method('introspect')
            ->with(
                self::FOREIGN_ACCESS_TOKEN,
                $this->callback(
                    fn(ParsedJws $jws): bool => $jws->getIssuer() === 'https://node-a.example.org',
                ),
                'refresh_token',
                $this->callback(
                    fn(IntrospectionAuthorization $caller): bool =>
                        $caller->getCallerId() === 'rs1' &&
                        $caller->getRole() === IntrospectionCallerRoleEnum::ResourceServer,
                ),
            )
            ->willReturn($answer);

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with($answer)
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    public function testInvokeAnswersATokenOfAnotherIssuerTheProxiedIntrospectorRefusesAsInactive(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->givenAForeignTokenAskedAbout($requestMock);

        $this->proxiedTokenIntrospectorMock->method('introspect')->willReturn(null);

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with(['active' => false])
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    /**
     * No answer from upstream is not a verdict on the token, so it is not answered as an inactive one, which a
     * resource server may cache. The failure was logged where it happened, and is not logged again.
     */
    public function testInvokeAnswersAFailureToGetAnAnswerUpstreamAsAServerError(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->givenAForeignTokenAskedAbout($requestMock);

        $this->proxiedTokenIntrospectorMock->method('introspect')
            ->willThrowException(UpstreamIntrospectionException::unavailable('No answer from the hub.'));

        $this->loggerServiceMock->expects($this->never())->method('error');
        $this->routesMock->expects($this->never())->method('newJsonResponse');

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonErrorResponse')
            ->with('server_error', 'Unable to process the introspection request.', 500)
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    /**
     * Anything else the proxied path throws (a misconfigured upstream, a release policy failure) is a server error
     * too, logged here.
     */
    public function testInvokeAnswersAnyOtherFailureOnTheProxiedPathAsAServerError(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->givenAForeignTokenAskedAbout($requestMock);

        $this->proxiedTokenIntrospectorMock->method('introspect')
            ->willThrowException(new ConfigurationError('The next hop is misconfigured.'));

        $this->loggerServiceMock->expects($this->once())->method('error');

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonErrorResponse')
            ->with('server_error', 'Unable to process the introspection request.', 500)
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    protected static function jws(array $header, array|string $payload): string
    {
        $segment = fn(string $json): string => rtrim(strtr(base64_encode($json), '+/', '-_'), '=');

        return $segment(json_encode((object)$header, JSON_THROW_ON_ERROR)) . '.' .
        $segment(is_string($payload) ? $payload : json_encode((object)$payload, JSON_THROW_ON_ERROR)) .
        '.c2lnbmF0dXJl';
    }


    public static function jwsValidatedHereProvider(): array
    {
        $nested = [];
        for ($level = 0; $level < 100; $level++) {
            $nested = ['x' => $nested];
        }

        return [
            // Their lifetime is judged as the JWS is parsed; the validator refuses them for the same reason.
            'another issuer\'s, expired' => [
                self::jws(['alg' => 'RS256'], ['iss' => 'https://node-a.example.org', 'exp' => time() - 3600]),
            ],
            'another issuer\'s, not yet valid' => [
                self::jws(['alg' => 'RS256'], ['iss' => 'https://node-a.example.org', 'nbf' => time() + 3600]),
            ],
            // RFC 7519 section 4.1.1: 'iss' is a string. A value of another type names no issuer, and is not made one.
            'naming an issuer which is a list' => [
                self::jws(['alg' => 'RS256'], ['iss' => ['https://node-a.example.org']]),
            ],
            'naming an issuer which is a number' => [self::jws(['alg' => 'RS256'], ['iss' => 42])],
            'naming an issuer which is true' => [self::jws(['alg' => 'RS256'], ['iss' => true])],
            // Valid JSON which PHP will not decode into an object, and which the library accepts.
            'this OP\'s, with a member name starting with NUL' => [
                self::jws(['alg' => 'RS256'], '{"iss":"https://op.example.org","x":{"\\u0000key":"value"}}'),
            ],
            'this OP\'s, nested deep' => [
                self::jws(['alg' => 'RS256'], ['iss' => 'https://op.example.org', 'x' => $nested]),
            ],
        ];
    }


    /**
     * What the library parses as a JWS is looked up as an access token of this OP unless it plainly names another
     * issuer, so that the validator, which parses it the same way, gives the answer and the reason.
     */
    #[DataProvider('jwsValidatedHereProvider')]
    public function testInvokeValidatesHereAJwsWhichDoesNotPlainlyNameAnotherIssuer(string $token): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn($this->createValidResolvedClientAuthenticationMethodMock('rs1'));
        $this->moduleConfigMock->method('getApiOAuth2TokenIntrospectionResourceServerClientIds')->willReturn(['rs1']);

        $this->requestParamsResolverMock
            ->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnMap([
                ['token', $requestMock, [HttpMethodsEnum::POST], $token],
                ['token_type_hint', $requestMock, [HttpMethodsEnum::POST], null],
            ]);

        $this->bearerTokenValidatorMock->expects($this->once())
            ->method('ensureValidAccessToken')
            ->with($token)
            ->willThrowException(new JwsException('refused'));
        $this->proxiedTokenIntrospectorMock->expects($this->never())->method('introspect');
        $this->oAuth2BridgeMock->expects($this->never())->method('decrypt');

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with(['active' => false])
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    public static function valuesWhichAreNotAJwsProvider(): array
    {
        $jws = self::jws(['alg' => 'RS256'], ['iss' => 'https://node-a.example.org']);

        return [
            'an encrypted refresh token' => ['def50200a1b2c3d4e5f60718293a4b5c6d7e8f90'],
            'four segments' => [$jws . '.c2ln'],
            'little but dots' => [$jws . str_repeat('.', 100000)],
            'a header which is not JSON' => ['bm90IGpzb24.eyJpc3MiOiJ4In0.c2ln'],
        ];
    }


    /**
     * What the library does not parse as a JWS can only be a refresh token of this OP.
     */
    #[DataProvider('valuesWhichAreNotAJwsProvider')]
    public function testInvokeLooksAValueTheLibraryDoesNotParseAsAJwsUpAsARefreshToken(string $token): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn($this->createValidResolvedClientAuthenticationMethodMock('client1'));

        $this->requestParamsResolverMock
            ->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnMap([
                ['token', $requestMock, [HttpMethodsEnum::POST], $token],
                ['token_type_hint', $requestMock, [HttpMethodsEnum::POST], 'access_token'],
            ]);

        $this->bearerTokenValidatorMock->expects($this->never())->method('ensureValidAccessToken');
        $this->proxiedTokenIntrospectorMock->expects($this->never())->method('introspect');
        $this->oAuth2BridgeMock->expects($this->once())
            ->method('decrypt')
            ->with($token)
            ->willThrowException(new Exception('Unable to decrypt'));

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with(['active' => false])
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    private function givenAForeignTokenAskedAbout(MockObject $requestMock): void
    {
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn($this->createValidResolvedClientAuthenticationMethodMock('rs1'));
        $this->moduleConfigMock->method('getApiOAuth2TokenIntrospectionResourceServerClientIds')->willReturn(['rs1']);

        $this->requestParamsResolverMock
            ->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnMap([
                ['token', $requestMock, [HttpMethodsEnum::POST], self::FOREIGN_ACCESS_TOKEN],
                ['token_type_hint', $requestMock, [HttpMethodsEnum::POST], null],
            ]);
    }


    public function testInvokeWithTokenTypeHintAccessToken(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn($this->createValidResolvedClientAuthenticationMethodMock('client2'));

        $this->requestParamsResolverMock
            ->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnMap([
                ['token', $requestMock, [HttpMethodsEnum::POST], self::ACCESS_TOKEN],
                ['token_type_hint', $requestMock, [HttpMethodsEnum::POST], 'access_token'],
            ]);

        $jwsMock = $this->createMock(ParsedJws::class);
        $jwsMock->method('getPayloadClaim')->with('scopes')->willReturn(['scope2']);
        $jwsMock->method('getAudience')->willReturn(['client2']);
        $jwsMock->method('getExpirationTime')->willReturn(1000);
        $jwsMock->method('getJwtId')->willReturn('jti2');

        $this->bearerTokenValidatorMock->expects($this->once())
            ->method('ensureValidAccessToken')
            ->with(self::ACCESS_TOKEN)
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
                ['token', $requestMock, [HttpMethodsEnum::POST], self::ACCESS_TOKEN],
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
            ->with(self::ACCESS_TOKEN)
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
                ['token', $requestMock, [HttpMethodsEnum::POST], self::ACCESS_TOKEN],
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
            ->with(self::ACCESS_TOKEN)
            ->willReturn($jwsMock);
        // Refused before anything is read about the token's user, and before the release policy is asked.
        $this->accessTokenRepositoryMock->expects($this->never())->method('findById');
        $this->userRepositoryMock->expects($this->never())->method('getUserEntityByIdentifier');
        $this->introspectionReleasePolicyFactoryMock->expects($this->never())->method('build');

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
        $this->introspectionReleasePolicyFactoryMock->expects($this->never())->method('build');

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
                ['token', $requestMock, [HttpMethodsEnum::POST], self::ACCESS_TOKEN],
                ['token_type_hint', $requestMock, [HttpMethodsEnum::POST], 'access_token'],
            ]);

        $jwsMock = $this->createMock(ParsedJws::class);
        $jwsMock->method('getPayloadClaim')->with('scopes')->willReturn(['openid']);
        $jwsMock->method('getAudience')->willReturn([]);
        $jwsMock->method('getExpirationTime')->willReturn(time() + 3600);

        $this->bearerTokenValidatorMock->expects($this->once())
            ->method('ensureValidAccessToken')
            ->with(self::ACCESS_TOKEN)
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
                ['token', $requestMock, [HttpMethodsEnum::POST], self::ACCESS_TOKEN],
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
            ->with(self::ACCESS_TOKEN)
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
                ['token', $requestMock, [HttpMethodsEnum::POST], self::ACCESS_TOKEN],
                ['token_type_hint', $requestMock, [HttpMethodsEnum::POST], 'access_token'],
            ]);

        $jwsMock = $this->createMock(ParsedJws::class);
        $jwsMock->method('getPayloadClaim')->with('scopes')->willReturn(['openid']);
        $jwsMock->method('getAudience')->willReturn(['other-client']);
        $jwsMock->method('getExpirationTime')->willReturn(1000);
        $jwsMock->method('getJwtId')->willReturn('served-jti');

        $this->bearerTokenValidatorMock->expects($this->once())
            ->method('ensureValidAccessToken')
            ->with(self::ACCESS_TOKEN)
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
                ['token', $requestMock, [HttpMethodsEnum::POST], self::ACCESS_TOKEN],
                ['token_type_hint', $requestMock, [HttpMethodsEnum::POST], 'access_token'],
            ]);

        $jwsMock = $this->createMock(ParsedJws::class);
        $jwsMock->method('getPayloadClaim')->with('scopes')->willReturn(['openid']);
        $jwsMock->method('getAudience')->willReturn(['some-client']);
        $jwsMock->method('getExpirationTime')->willReturn(1000);
        $jwsMock->method('getJwtId')->willReturn('some-jti');

        $this->bearerTokenValidatorMock->expects($this->once())
            ->method('ensureValidAccessToken')
            ->with(self::ACCESS_TOKEN)
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
                ['token', $requestMock, [HttpMethodsEnum::POST], self::ACCESS_TOKEN],
                ['token_type_hint', $requestMock, [HttpMethodsEnum::POST], 'access_token'],
            ]);

        $jwsMock = $this->createMock(ParsedJws::class);
        $jwsMock->method('getPayloadClaim')->with('scopes')->willReturn(['openid']);
        $jwsMock->method('getAudience')->willReturn(['other-client']);
        $jwsMock->method('getExpirationTime')->willReturn(1000);
        $jwsMock->method('getJwtId')->willReturn('hub-jti');

        $this->bearerTokenValidatorMock->expects($this->once())
            ->method('ensureValidAccessToken')
            ->with(self::ACCESS_TOKEN)
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
                ['token', $requestMock, [HttpMethodsEnum::POST], self::ACCESS_TOKEN],
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
            ->with(self::ACCESS_TOKEN)
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
        // A policy is only ever asked about a token which is active.
        $this->introspectionReleasePolicyFactoryMock->expects($this->never())->method('build');

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
        $this->introspectionReleasePolicyFactoryMock->expects($this->never())->method('build');

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
        $this->givenTheResolvedSubject('resolved-subject');

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
                ['token', $requestMock, [HttpMethodsEnum::POST], self::ACCESS_TOKEN],
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
                ['token', $requestMock, [HttpMethodsEnum::POST], self::ACCESS_TOKEN],
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
                ['token', $requestMock, [HttpMethodsEnum::POST], self::ACCESS_TOKEN],
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


    /**
     * The release policy the deployment configured: answers every question with what $decide returns, and keeps
     * what it was asked in $asked.
     *
     * @param \Closure(): \SimpleSAML\Module\oidc\ValueAbstracts\IntrospectionReleaseDecision $decide
     */
    private function givenReleasePolicy(Closure $decide): object
    {
        $policy = new class ($decide) implements IntrospectionReleasePolicyInterface {
            public array $asked = [];


            public function __construct(private readonly Closure $decide)
            {
            }


            public function decide(
                IntrospectionAuthorization $caller,
                IntrospectedTokenOrigin $origin,
                array $grantedScopes,
                array $tokenMembers,
            ): IntrospectionReleaseDecision {
                $this->asked[] = [$caller, $origin, $grantedScopes, $tokenMembers];

                return ($this->decide)();
            }
        };

        $this->introspectionReleasePolicyFactoryMock = $this->createMock(IntrospectionReleasePolicyFactory::class);
        $this->introspectionReleasePolicyFactoryMock->method('build')->willReturn($policy);

        return $policy;
    }


    private function givenIntrospectableRefreshToken(MockObject $requestMock, array $payload): void
    {
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn($this->createValidResolvedClientAuthenticationMethodMock('client1'));

        $this->requestParamsResolverMock
            ->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnMap([
                ['token', $requestMock, [HttpMethodsEnum::POST], 'valid-refresh-token'],
                ['token_type_hint', $requestMock, [HttpMethodsEnum::POST], 'refresh_token'],
            ]);

        $this->oAuth2BridgeMock->method('decrypt')
            ->with('valid-refresh-token')
            ->willReturn(json_encode([
                'expire_time' => time() + 3600,
                'refresh_token_id' => 'ref-1',
                'client_id' => 'client1',
                ...$payload,
            ]));

        $this->refreshTokenRepositoryMock->method('isRefreshTokenRevoked')->with('ref-1')->willReturn(false);
    }


    /**
     * The policy is asked once, about an active token, with who asked and in which role, where the token comes
     * from, the scopes it was granted and its members as they stand before the decision: without the user claims,
     * which are only read for the scopes the decision releases.
     */
    public function testInvokeAsksTheReleasePolicyAboutAnActiveAccessToken(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->givenIntrospectableAccessToken($requestMock, 'jti1', ['openid', 'profile']);
        $this->givenAccessTokenRecord('jti1', 'user1');
        $this->givenUserRecord('user1', ['displayName' => ['Ada']]);
        $policy = $this->givenReleasePolicy(fn(): IntrospectionReleaseDecision =>
            IntrospectionReleaseDecision::releaseAll());

        $this->claimTranslatorExtractorMock->method('extract')->willReturn(['name' => 'Ada']);
        $this->routesMock->method('newJsonResponse')->willReturn($this->createMock(JsonResponse::class));

        $this->sut()->__invoke($requestMock);

        $this->assertCount(1, $policy->asked);
        [$caller, $origin, $grantedScopes, $tokenMembers] = $policy->asked[0];
        $this->assertSame(IntrospectionCallerRoleEnum::Client, $caller->getRole());
        $this->assertSame('client1', $caller->getCallerId());
        $this->assertTrue($origin->isLocal());
        $this->assertSame('https://op.example.org', $origin->getIssuer());
        $this->assertTrue($origin->isIssuerVerified());
        $this->assertSame(['openid', 'profile'], $grantedScopes);
        $this->assertSame(
            [
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
            ],
            $tokenMembers,
        );
    }


    public function testInvokeAsksTheReleasePolicyAboutAnActiveRefreshToken(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->givenIntrospectableRefreshToken($requestMock, ['scopes' => ['openid', 'offline_access'], 'sub' => 's1']);
        $policy = $this->givenReleasePolicy(fn(): IntrospectionReleaseDecision =>
            IntrospectionReleaseDecision::releaseAll());

        $this->routesMock->method('newJsonResponse')->willReturn($this->createMock(JsonResponse::class));

        $this->sut()->__invoke($requestMock);

        $this->assertCount(1, $policy->asked);
        [$caller, $origin, $grantedScopes, $tokenMembers] = $policy->asked[0];
        $this->assertSame('client1', $caller->getCallerId());
        $this->assertTrue($origin->isLocal());
        $this->assertSame('https://op.example.org', $origin->getIssuer());
        $this->assertSame(['openid', 'offline_access'], $grantedScopes);
        $this->assertSame('openid offline_access', $tokenMembers['scope']);
        $this->assertSame('s1', $tokenMembers['sub']);
        $this->assertSame('ref-1', $tokenMembers['jti']);
    }


    /**
     * A denial is answered exactly as an inactive token is (RFC 7662 section 2.2), and nothing about the token's
     * user is read for it.
     */
    public function testInvokeAnswersAnAccessTokenThePolicyDeniesAsInactive(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->givenIntrospectableAccessToken($requestMock, 'jti1', ['openid', 'profile']);
        $this->givenAccessTokenRecord('jti1', 'user1');
        $this->givenUserRecord('user1', ['displayName' => ['Ada']]);
        $this->givenReleasePolicy(fn(): IntrospectionReleaseDecision => IntrospectionReleaseDecision::deny());

        $this->claimTranslatorExtractorMock->expects($this->never())->method('extract');
        $this->loggerServiceMock->expects($this->once())
            ->method('notice')
            ->with($this->stringContains('denies client client1 the answer about access token jti1'));

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with(['active' => false])
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    public function testInvokeAnswersARefreshTokenThePolicyDeniesAsInactive(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->givenIntrospectableRefreshToken($requestMock, ['scopes' => ['openid'], 'sub' => 's1']);
        $this->givenReleasePolicy(fn(): IntrospectionReleaseDecision => IntrospectionReleaseDecision::deny());

        $this->loggerServiceMock->expects($this->once())
            ->method('notice')
            ->with($this->stringContains('denies client client1 the answer about refresh token ref-1'));

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with(['active' => false])
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    /**
     * The policy is told who asked, and in which role: the caller the endpoint authenticated, not the client the
     * token was issued to, so a deployment can decide per resource server, for the hub or for the administrative
     * path.
     */
    #[DataProvider('callerRoleProvider')]
    public function testInvokeTellsTheReleasePolicyWhoAskedInWhichRole(
        ?string $clientId,
        ?string $roleListGetter,
        IntrospectionCallerRoleEnum $expectedRole,
        string $expectedCallerId,
    ): void {
        $requestMock = $this->createMock(Request::class);

        if (is_null($clientId)) {
            $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')->willReturn(null);
            $this->apiAuthorizationMock->method('requireCallerForAnyOfScope')->willReturn('ops-token');
        } else {
            $this->moduleConfigMock->method((string)$roleListGetter)->willReturn([$clientId]);
            $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
                ->willReturn($this->createValidResolvedClientAuthenticationMethodMock($clientId));
        }

        $this->requestParamsResolverMock
            ->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnMap([
                ['token', $requestMock, [HttpMethodsEnum::POST], self::ACCESS_TOKEN],
                ['token_type_hint', $requestMock, [HttpMethodsEnum::POST], 'access_token'],
            ]);

        $jwsMock = $this->createMock(ParsedJws::class);
        $jwsMock->method('getPayloadClaim')->with('scopes')->willReturn(['openid']);
        $jwsMock->method('getAudience')->willReturn(['client1']);
        $jwsMock->method('getExpirationTime')->willReturn(1000);
        $jwsMock->method('getJwtId')->willReturn('jti1');
        $this->bearerTokenValidatorMock->method('ensureValidAccessToken')->willReturn($jwsMock);
        $this->givenAccessTokenRecord('jti1');

        $policy = $this->givenReleasePolicy(fn(): IntrospectionReleaseDecision =>
            IntrospectionReleaseDecision::releaseAll());

        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with($this->callback(fn(array $data): bool => $data['active'] === true
                && $data['client_id'] === 'client1'))
            ->willReturn($this->createMock(JsonResponse::class));

        $this->sut()->__invoke($requestMock);

        $this->assertCount(1, $policy->asked);
        $this->assertSame($expectedRole, $policy->asked[0][0]->getRole());
        $this->assertSame($expectedCallerId, $policy->asked[0][0]->getCallerId());
    }


    public static function callerRoleProvider(): array
    {
        return [
            'a resource server' => [
                'rs1',
                'getApiOAuth2TokenIntrospectionResourceServerClientIds',
                IntrospectionCallerRoleEnum::ResourceServer,
                'rs1',
            ],
            'the upstream hub' => [
                'hub1',
                'getApiOAuth2TokenIntrospectionUpstreamHubClientIds',
                IntrospectionCallerRoleEnum::UpstreamHub,
                'hub1',
            ],
            'an API token' => [null, null, IntrospectionCallerRoleEnum::Administrative, 'ops-token'],
        ];
    }


    /**
     * Without a token_type_hint, a denied access token is answered as inactive like any other, and the policy is
     * asked once. The search ends there: a JWS is never looked up as a refresh token, so no decryption is tried
     * (and no decryption failure logged) for a token which was found.
     */
    public function testInvokeAnswersADeniedAccessTokenWithoutATokenTypeHintAsInactive(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->givenIntrospectableAccessToken($requestMock, 'jti1', ['openid'], tokenTypeHint: null);
        $this->givenAccessTokenRecord('jti1');
        $policy = $this->givenReleasePolicy(fn(): IntrospectionReleaseDecision => IntrospectionReleaseDecision::deny());

        $this->oAuth2BridgeMock->expects($this->never())->method('decrypt');

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with(['active' => false])
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
        $this->assertCount(1, $policy->asked);
    }


    /**
     * The user claims are read for the released scopes only, so a scope taken away takes its claims with it, and
     * the 'scope' member names what was released, in the token's order.
     */
    public function testInvokeReleasesTheUserClaimsOfTheReleasedScopesOnly(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->givenIntrospectableAccessToken($requestMock, 'jti1', ['openid', 'profile', 'email']);
        $this->givenAccessTokenRecord('jti1', 'user1');
        $this->givenUserRecord('user1', ['mail' => ['ada@example.org']]);
        $this->givenReleasePolicy(fn(): IntrospectionReleaseDecision =>
            IntrospectionReleaseDecision::release(['email', 'openid', 'not-granted']));

        $this->claimTranslatorExtractorMock->expects($this->once())
            ->method('extract')
            ->with(['openid', 'email'], ['mail' => ['ada@example.org']])
            ->willReturn(['email' => 'ada@example.org']);

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with([
                'active' => true,
                'scope' => 'openid email',
                'client_id' => 'client1',
                'token_type' => 'Bearer',
                'exp' => 1000,
                'iat' => 500,
                'sub' => 'token-subject',
                'aud' => ['client1'],
                'iss' => 'iss1',
                'jti' => 'jti1',
                'email' => 'ada@example.org',
            ])
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    public function testInvokeLeavesTheScopeOutWhenNoScopeIsReleased(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->givenIntrospectableAccessToken($requestMock, 'jti1', ['openid', 'profile']);
        $this->givenAccessTokenRecord('jti1', 'user1');
        $this->givenUserRecord('user1', ['displayName' => ['Ada']]);
        $this->givenReleasePolicy(fn(): IntrospectionReleaseDecision => IntrospectionReleaseDecision::release([]));

        $this->claimTranslatorExtractorMock->expects($this->once())
            ->method('extract')
            ->with([], ['displayName' => ['Ada']])
            ->willReturn([]);

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with($this->callback(fn(array $data): bool => $data['active'] === true
                && !array_key_exists('scope', $data)
                && $data['sub'] === 'token-subject'))
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    /**
     * 'scope' is not a protected member: a decision may release a scope's claims and still leave the 'scope' member
     * itself out of the answer.
     */
    public function testInvokeWithholdsTheScopeMemberWhileReleasingTheScopesClaims(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->givenIntrospectableAccessToken($requestMock, 'jti1', ['openid', 'profile']);
        $this->givenAccessTokenRecord('jti1', 'user1');
        $this->givenUserRecord('user1', ['displayName' => ['Ada']]);
        $this->givenReleasePolicy(fn(): IntrospectionReleaseDecision =>
            IntrospectionReleaseDecision::release(['profile'], ['scope']));

        $this->claimTranslatorExtractorMock->expects($this->once())
            ->method('extract')
            ->with(['profile'], ['displayName' => ['Ada']])
            ->willReturn(['name' => 'Ada']);

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with($this->callback(fn(array $data): bool => $data['active'] === true
                && !array_key_exists('scope', $data)
                && $data['name'] === 'Ada'
                && $data['sub'] === 'token-subject'))
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    /**
     * Withholding is applied to the assembled answer, last, so a withheld name does not come back from either
     * side: not 'sub' as the token's member, and not 'sub' as the user claim the 'openid' scope releases, which
     * for a token minted before the module wrote 'typ' would otherwise stand in its place.
     */
    #[DataProvider('tokenTypeProvider')]
    public function testInvokeWithholdsTheNamedMembersFromTheAssembledAnswer(?string $type, string $tokenSubject): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->givenIntrospectableAccessToken($requestMock, 'jti1', ['openid', 'profile'], $tokenSubject, $type);
        $this->givenAccessTokenRecord('jti1', 'user1');
        $this->givenUserRecord('user1', ['displayName' => ['Ada']]);
        $this->givenTheResolvedSubject('user-claim-subject');
        $this->givenReleasePolicy(fn(): IntrospectionReleaseDecision =>
            IntrospectionReleaseDecision::release(withheldMembers: ['sub', 'name']));

        $this->claimTranslatorExtractorMock->method('extract')
            ->willReturn(['sub' => 'user-claim-subject', 'name' => 'Ada', 'given_name' => 'Ada']);

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
                'aud' => ['client1'],
                'iss' => 'iss1',
                'jti' => 'jti1',
                'given_name' => 'Ada',
            ])
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    /**
     * A token with a 'typ' header carries the resolved subject itself; one minted before carries the internal user
     * identifier, which the resolved subject replaces.
     */
    public static function tokenTypeProvider(): array
    {
        return [
            'a token with a typ header' => ['at+jwt', 'token-subject'],
            'a token minted before the module wrote typ' => [null, 'internal-user-id'],
        ];
    }


    /**
     * A token minted before the module wrote 'typ' carries the internal user identifier as its 'sub'; the answer
     * reports the resolved subject the granted 'openid' scope releases instead. That is settled before the policy
     * is asked, so a policy which takes 'openid' away does not bring the internal identifier back: a decision can
     * only take away, and the internal identifier is not in the answer the policy restricts.
     */
    #[DataProvider('scopesWithoutOpenIdProvider')]
    public function testInvokeNeverReportsTheInternalIdentifierOfALegacyTokenWhoseOpenIdScopeIsTakenAway(
        array $releasedScopes,
    ): void {
        $requestMock = $this->createMock(Request::class);
        $this->givenIntrospectableAccessToken($requestMock, 'jti1', ['openid', 'profile'], 'internal-user-id', null);
        $this->givenAccessTokenRecord('jti1', 'internal-user-id');
        $this->givenUserRecord('internal-user-id', ['displayName' => ['Ada']]);
        $this->givenTheResolvedSubject('resolved-subject');
        $policy = $this->givenReleasePolicy(fn(): IntrospectionReleaseDecision =>
            IntrospectionReleaseDecision::release($releasedScopes));

        $this->claimTranslatorExtractorMock->method('extract')
            ->willReturnCallback(fn(array $scopes): array => array_merge(
                in_array('openid', $scopes, true) ? ['sub' => 'resolved-subject'] : [],
                in_array('profile', $scopes, true) ? ['name' => 'Ada'] : [],
            ));

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with($this->callback(fn(array $data): bool => $data['active'] === true
                && $data['sub'] === 'resolved-subject'
                && !in_array('internal-user-id', $data, true)
                && array_key_exists('name', $data) === in_array('profile', $releasedScopes, true)))
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));

        // The subject the policy is shown is the one the answer reports.
        $this->assertSame('resolved-subject', $policy->asked[0][3]['sub']);
    }


    public static function scopesWithoutOpenIdProvider(): array
    {
        return [
            'profile only' => [['profile']],
            'no scope' => [[]],
        ];
    }


    /**
     * Only the subject of a token minted before 'typ' is resolved ahead of the policy. An identity claim with an
     * invalid value is refused wherever the 'openid' scope releases it, but a policy which takes 'openid' away
     * releases no identity claim, so that value must not fail the answer before the policy has decided. With the
     * real extractor, since the refusal is its own.
     */
    public function testInvokeResolvesOnlyTheSubjectOfALegacyTokenBeforeThePolicyDecides(): void
    {
        $claimTranslatorExtractor = new ClaimTranslatorExtractor(
            ['uid'],
            new ClaimSetEntityFactory(),
            [],
            ['voperson_id' => ['voPersonID'], 'name' => ['displayName']],
            [],
            ['voperson_id'],
        );

        $requestMock = $this->createMock(Request::class);
        $this->givenIntrospectableAccessToken($requestMock, 'jti1', ['openid', 'profile'], 'internal-user-id', null);
        $this->givenAccessTokenRecord('jti1', 'internal-user-id');
        $this->givenUserRecord(
            'internal-user-id',
            ['uid' => ['ada-subject'], 'voPersonID' => [''], 'displayName' => ['Ada']],
        );
        $policy = $this->givenReleasePolicy(fn(): IntrospectionReleaseDecision =>
            IntrospectionReleaseDecision::release(['profile']));

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->never())->method('newJsonErrorResponse');
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with($this->callback(fn(array $data): bool => $data['active'] === true
                && $data['scope'] === 'profile'
                && $data['sub'] === 'ada-subject'
                && $data['name'] === 'Ada'
                && !array_key_exists('voperson_id', $data)))
            ->willReturn($responseMock);

        $this->assertSame(
            $responseMock,
            $this->sut(claimTranslatorExtractor: $claimTranslatorExtractor)->__invoke($requestMock),
        );
        $this->assertSame('ada-subject', $policy->asked[0][3]['sub']);
    }


    public function testInvokeAppliesTheDecisionToARefreshToken(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->givenIntrospectableRefreshToken($requestMock, ['scopes' => ['openid', 'offline_access'], 'sub' => 's1']);
        $this->givenReleasePolicy(fn(): IntrospectionReleaseDecision =>
            IntrospectionReleaseDecision::release(['openid'], ['sub']));

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with($this->callback(fn(array $data): bool => $data['active'] === true
                && $data['scope'] === 'openid'
                && !array_key_exists('sub', $data)
                && $data['client_id'] === 'client1'
                && $data['aud'] === 'client1'
                && $data['jti'] === 'ref-1'))
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    /**
     * A policy which fails, or which names a member no decision may withhold, is the OP's failure, not a verdict on
     * the token: a server_error, never an answer a resource server would cache.
     */
    #[DataProvider('releasePolicyFailureProvider')]
    public function testInvokeAnswersAReleasePolicyFailureAsAServerError(Closure $decide, string $failure): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->givenIntrospectableAccessToken($requestMock, 'jti1', ['openid']);
        $this->givenAccessTokenRecord('jti1', 'user1');
        $this->givenUserRecord('user1', []);
        $this->givenReleasePolicy($decide);

        $this->loggerServiceMock->expects($this->once())
            ->method('error')
            ->with($this->stringContains($failure));
        $this->routesMock->expects($this->never())->method('newJsonResponse');

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonErrorResponse')
            ->with('server_error', 'Unable to process the introspection request.', 500)
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }


    public static function releasePolicyFailureProvider(): array
    {
        return [
            'the policy throws' => [
                fn(): IntrospectionReleaseDecision => throw new RuntimeException('Policy store unreachable'),
                'Policy store unreachable',
            ],
            'the policy withholds a protected member' => [
                fn(): IntrospectionReleaseDecision => IntrospectionReleaseDecision::release(withheldMembers: ['iss']),
                'may not withhold the member iss',
            ],
        ];
    }


    public function testInvokeAnswersAReleasePolicyWhichCanNotBeBuiltAsAServerError(): void
    {
        $requestMock = $this->createMock(Request::class);
        $this->givenIntrospectableAccessToken($requestMock, 'jti1', ['openid']);
        $this->givenAccessTokenRecord('jti1', 'user1');
        $this->givenUserRecord('user1', []);

        $this->introspectionReleasePolicyFactoryMock = $this->createMock(IntrospectionReleasePolicyFactory::class);
        $this->introspectionReleasePolicyFactoryMock->method('build')
            ->willThrowException(new ConfigurationError('not a class implementing'));

        $this->loggerServiceMock->expects($this->once())
            ->method('error')
            ->with($this->stringContains('not a class implementing'), ['exception' => ConfigurationError::class]);
        $this->routesMock->expects($this->never())->method('newJsonResponse');

        $responseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonErrorResponse')
            ->with('server_error', 'Unable to process the introspection request.', 500)
            ->willReturn($responseMock);

        $this->assertSame($responseMock, $this->sut()->__invoke($requestMock));
    }
}
