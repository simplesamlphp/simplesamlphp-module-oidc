<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers;

use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Error\UserNotFound;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum;
use SimpleSAML\Module\oidc\Controllers\Traits\RequestTrait;
use SimpleSAML\Module\oidc\Controllers\UserInfoController;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\ResourceServer;
use SimpleSAML\Module\oidc\Server\Validators\BearerTokenValidator;
use SimpleSAML\Module\oidc\Services\ErrorResponder;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Utils\Routes;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;

/**
 * @covers \SimpleSAML\Module\oidc\Controllers\UserInfoController
 */
#[AllowMockObjectsWithoutExpectations]
class UserInfoControllerTest extends TestCase
{
    protected const string USERINFO_URL = 'https://op.example.org/module.php/oidc/userinfo';


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

    protected MockObject $moduleConfigMock;


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
        $this->routesMock->method('urlUserInfo')->willReturn(self::USERINFO_URL);
        $this->routesMock->method('newJsonResponse')->willReturnCallback(
            fn (
                array|null $data = null,
                int $status = 200,
                array $headers = [],
                bool $json = false,
            ) => new JsonResponse($data, $status, $headers, $json),
        );

        $this->symfonyRequestMock = $this->createMock(Request::class);
        $this->symfonyResponseMock = $this->createMock(Response::class);
        $this->responseHeaderBagMock = $this->createMock(ResponseHeaderBag::class);
        $this->symfonyResponseMock->headers = $this->responseHeaderBagMock;

        $this->httpFoundationFactoryMock = $this->createMock(HttpFoundationFactory::class);
        $this->httpFoundationFactoryMock->method('createResponse')->willReturn($this->symfonyResponseMock);
        $this->psrHttpBridgeMock->method('getHttpFoundationFactory')->willReturn($this->httpFoundationFactoryMock);

        $this->psrHttpFactoryMock = $this->createMock(PsrHttpFactory::class);
        $this->psrHttpFactoryMock->method('createRequest')->willReturn($this->serverRequestMock);
        $this->psrHttpBridgeMock->method('getPsrHttpFactory')->willReturn($this->psrHttpFactoryMock);

        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getDpopSigningAlgorithms')->willReturn(['ES256']);
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
            $this->moduleConfigMock,
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
     * A request authorised with the given token attributes, against a stored token for a user whose record
     * releases what the extractor is told to release.
     *
     * @param array<string, mixed> $tokenAttributes What BearerTokenValidator put on the request.
     * @param array<string, mixed> $extracted What the extractor releases for the token's scopes.
     */
    protected function userInfoFor(array $tokenAttributes, array $extracted): array
    {
        $this->serverRequestMock->method('getMethod')->willReturn('GET');
        $this->authorizationServerRequestMock->method('getAttribute')
            ->willReturnCallback(fn(string $name): mixed => $tokenAttributes[$name] ?? null);
        $this->resourceServerMock->method('validateAuthenticatedRequest')
            ->willReturn($this->authorizationServerRequestMock);
        $this->accessTokenEntityMock->method('getUserIdentifier')->willReturn('userid');
        $this->accessTokenEntityMock->method('getRequestedClaims')->willReturn([]);
        $this->accessTokenRepositoryMock->method('findById')->willReturn($this->accessTokenEntityMock);
        $this->userEntityMock->method('getClaims')->willReturn(['uid' => ['userid']]);
        $this->userRepositoryMock->method('getUserEntityByIdentifier')->willReturn($this->userEntityMock);
        $this->claimTranslatorExtractorMock->method('extract')->willReturn($extracted);
        $this->claimTranslatorExtractorMock->method('extractAdditionalUserInfoClaims')->willReturn([]);

        $response = $this->mock()->__invoke($this->serverRequestMock);

        return json_decode((string) $response->getContent(), true, 512, JSON_THROW_ON_ERROR);
    }


    /**
     * The subject is the one the presented access token carries (resolved when it was minted and shared with
     * the ID token issued alongside), not the one the 'sub' translation yields now: an attribute which changed
     * since must not make this response contradict that ID token (OpenID Connect Core 1.0 section 5.3.2). And
     * it is there even when the translation yields nothing ("The sub (subject) Claim MUST always be returned
     * in the UserInfo Response"), which a 'sub' => [] translation left out before.
     */
    #[DataProvider('subjectFromTheTokenProvider')]
    public function testTakesTheSubjectFromAnAtJwtAccessToken(array $extracted, string $tokenSubject): void
    {
        $claims = $this->userInfoFor(
            [
                'oauth_access_token_id' => 'tokenid',
                'oauth_scopes' => ['openid', 'email'],
                'oauth_user_id' => $tokenSubject,
                'oauth_access_token_typ' => 'at+jwt',
            ],
            $extracted,
        );

        $this->assertSame($tokenSubject, $claims['sub']);
        $this->assertSame('userid@localhost.localdomain', $claims['email']);
    }


    public static function subjectFromTheTokenProvider(): array
    {
        return [
            'the translation yields another value now' => [
                ['sub' => 'subject-now', 'email' => 'userid@localhost.localdomain'],
                'subject-from-token',
            ],
            'the translation yields nothing' => [
                ['email' => 'userid@localhost.localdomain'],
                'subject-from-token',
            ],
            'the token carries the falsy but valid subject "0"' => [
                ['sub' => 'subject-now', 'email' => 'userid@localhost.localdomain'],
                '0',
            ],
        ];
    }


    /**
     * An access token minted before the module wrote a 'typ' header carries the internal user identifier as
     * its 'sub', not the resolved subject, so for such a token the 'sub' the 'openid' scope releases stands --
     * as it did when that token's ID token was issued -- for the rest of the token's lifetime.
     */
    public function testKeepsTheReleasedSubjectForALegacyAccessToken(): void
    {
        $claims = $this->userInfoFor(
            [
                'oauth_access_token_id' => 'tokenid',
                'oauth_scopes' => ['openid', 'email'],
                'oauth_user_id' => 'userid',
                'oauth_access_token_typ' => null,
            ],
            ['sub' => 'subject-now', 'email' => 'userid@localhost.localdomain'],
        );

        $this->assertSame('subject-now', $claims['sub']);
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
                $this->moduleConfigMock,
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


    /**
     * @return array<string,array{0:callable():\SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException,1:int,2:?string,3:?string}>
     */
    public static function refusalProvider(): array
    {
        return [
            'a refused token' => [
                static fn(): OidcServerException => OidcServerException::invalidToken('Access token has been revoked'),
                401,
                'Bearer error="invalid_token"',
                'invalid_token',
            ],
            'no token' => [
                static fn(): OidcServerException => OidcServerException::missingToken('No Bearer access token.'),
                401,
                'Bearer',
                null,
            ],
            'a token refused under the DPoP scheme' => [
                static fn(): OidcServerException => OidcServerException::invalidToken(
                    'The access token is not a DPoP-bound access token.',
                    null,
                    'DPoP error="invalid_token", algs="ES256"',
                ),
                401,
                'DPoP error="invalid_token", algs="ES256"',
                'invalid_token',
            ],
            'a refused DPoP proof' => [
                static fn(): OidcServerException => OidcServerException::invalidDpopProof(
                    'The DPoP proof has been used before.',
                    'DPoP error="invalid_dpop_proof", algs="ES256"',
                ),
                401,
                'DPoP error="invalid_dpop_proof", algs="ES256"',
                'invalid_dpop_proof',
            ],
            'a token presented more than one way' => [
                static fn(): OidcServerException => OidcServerException::multipleAccessTokenMethods(
                    'Bearer error="invalid_request"',
                ),
                400,
                'Bearer error="invalid_request"',
                'invalid_request',
            ],
            'a failure of the OP while checking the token' => [
                static fn(): OidcServerException => OidcServerException::serverError(
                    'The access token could not be checked.',
                ),
                500,
                null,
                'server_error',
            ],
        ];
    }


    /**
     * The endpoint refuses as RFC 6750 section 3 has it (OpenID Connect Core 1.0 section 5.3.3): the challenge
     * names the error for a token which was refused, and is the scheme alone, with no body, for a request which
     * carried none. A failure of the OP's own is a server error, with no challenge. Answered through the real
     * error responder and bridge, since the response is what is under test. Every refusal carries the CORS
     * headers, the challenge exposed, so that a JavaScript client can read it (RFC 9449 section 7.1).
     *
     * @param callable():\SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException $refusal
     */
    #[DataProvider('refusalProvider')]
    public function testAnswersARefusalAsRfc6750HasIt(
        callable $refusal,
        int $status,
        ?string $challenge,
        ?string $error,
    ): void {
        $this->resourceServerMock->method('validateAuthenticatedRequest')->willThrowException($refusal());

        $response = $this->userInfoControllerWithRealResponses()
            ->userInfo(Request::create('https://op.example.org/oidc/userinfo'));

        $this->assertSame($status, $response->getStatusCode());
        $this->assertSame($challenge, $response->headers->get('WWW-Authenticate'));
        $this->assertSame('*', $response->headers->get('Access-Control-Allow-Origin'));
        $this->assertSame('WWW-Authenticate', $response->headers->get('Access-Control-Expose-Headers'));

        if ($error === null) {
            $this->assertSame('', $response->getContent());
            $this->assertFalse($response->headers->has('Content-Type'));
            return;
        }

        $body = json_decode((string)$response->getContent(), true, 512, JSON_THROW_ON_ERROR);

        $this->assertIsArray($body);
        $this->assertSame($error, $body['error']);
    }


    /**
     * The token is checked against the URL this OP publishes for the endpoint, which the `htu` of a DPoP proof has
     * to name.
     */
    public function testChecksTheTokenForThePublishedUserInfoUrl(): void
    {
        $this->serverRequestMock->method('getMethod')->willReturn('GET');
        $this->resourceServerMock->expects($this->once())->method('validateAuthenticatedRequest')
            ->with($this->serverRequestMock, self::USERINFO_URL)
            ->willThrowException(OidcServerException::missingToken());

        $this->expectException(OidcServerException::class);

        $this->mock()->__invoke($this->serverRequestMock);
    }


    /**
     * A preflight allows the `DPoP` request header, for a client which sends a proof (RFC 9449).
     */
    public function testAllowsTheDpopHeaderInAPreflight(): void
    {
        $this->allowedOriginRepositoryMock->method('has')->with('https://rp.example.org')->willReturn(true);
        $request = Request::create('https://op.example.org/oidc/userinfo', 'OPTIONS');
        $request->headers->set('Origin', 'https://rp.example.org');

        $response = $this->userInfoControllerWithRealResponses()->userInfo($request);

        $this->assertSame(204, $response->getStatusCode());
        $this->assertSame(
            'Authorization, X-Requested-With, DPoP',
            $response->headers->get('Access-Control-Allow-Headers'),
        );
        $this->assertSame('https://rp.example.org', $response->headers->get('Access-Control-Allow-Origin'));
    }


    /**
     * A refused preflight gets no CORS headers: a preflight passes only with a success status, so they would
     * grant nothing, and an origin which is not allowed is not told otherwise.
     */
    public function testAnswersARefusedPreflightWithoutTheCorsHeaders(): void
    {
        $this->allowedOriginRepositoryMock->method('has')->willReturn(false);
        $request = Request::create('https://op.example.org/oidc/userinfo', 'OPTIONS');
        $request->headers->set('Origin', 'https://elsewhere.example.org');

        $response = $this->userInfoControllerWithRealResponses()->userInfo($request);

        $this->assertSame(401, $response->getStatusCode());
        $this->assertFalse($response->headers->has('Access-Control-Allow-Origin'));
        $this->assertFalse($response->headers->has('Access-Control-Expose-Headers'));
    }


    /**
     * The controller with the real error responder and bridge, for tests about the response itself.
     */
    protected function userInfoControllerWithRealResponses(): UserInfoController
    {
        $psr17Factory = new Psr17Factory();
        $psrHttpBridge = new PsrHttpBridge(
            new HttpFoundationFactory(),
            $psr17Factory,
            $psr17Factory,
            $psr17Factory,
            $psr17Factory,
        );

        return new UserInfoController(
            $this->resourceServerMock,
            $this->accessTokenRepositoryMock,
            $this->userRepositoryMock,
            $this->allowedOriginRepositoryMock,
            $this->claimTranslatorExtractorMock,
            $psrHttpBridge,
            new ErrorResponder($psrHttpBridge, $this->createStub(LoggerService::class)),
            $this->routesMock,
            $this->moduleConfigMock,
        );
    }


    /**
     * The response to a request with an access token of the given scopes and flow, presented under the given
     * scheme, through the real error responder and bridge.
     *
     * @param string[]|null $scopes Null for a token which carries no scopes claim.
     */
    protected function userInfoResponseFor(?array $scopes, ?FlowTypeEnum $flowType, string $scheme): Response
    {
        $attributes = [
            'oauth_access_token_id' => 'tokenid',
            'oauth_scopes' => $scopes,
            'oauth_user_id' => 'the-subject',
            'oauth_access_token_typ' => 'at+jwt',
            BearerTokenValidator::ATTRIBUTE_ACCESS_TOKEN_SCHEME => $scheme,
        ];
        $this->authorizationServerRequestMock->method('getAttribute')
            ->willReturnCallback(fn(string $name): mixed => $attributes[$name] ?? null);
        $this->resourceServerMock->method('validateAuthenticatedRequest')
            ->willReturn($this->authorizationServerRequestMock);
        $this->accessTokenEntityMock->method('getFlowTypeEnum')->willReturn($flowType);
        $this->accessTokenEntityMock->method('getUserIdentifier')->willReturn('userid');
        $this->accessTokenEntityMock->method('getRequestedClaims')->willReturn([]);
        $this->accessTokenRepositoryMock->method('findById')->willReturn($this->accessTokenEntityMock);
        $this->userEntityMock->method('getClaims')->willReturn(['uid' => ['userid']]);
        $this->userRepositoryMock->method('getUserEntityByIdentifier')->willReturn($this->userEntityMock);
        $this->claimTranslatorExtractorMock->method('extract')
            ->willReturn(['email' => 'userid@localhost.localdomain']);
        $this->claimTranslatorExtractorMock->method('extractAdditionalUserInfoClaims')->willReturn([]);

        return $this->userInfoControllerWithRealResponses()
            ->userInfo(Request::create('https://op.example.org/oidc/userinfo'));
    }


    /**
     * @return array<string, array{0: ?string[], 1: ?\SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum}>
     */
    public static function tokenWithoutTheOpenIdScopeProvider(): array
    {
        return [
            'a plain OAuth 2.0 token' => [['profile', 'email'], FlowTypeEnum::OAuth2AuthorizationCode],
            'a plain OAuth 2.0 token granted no scope, without a scopes claim' => [
                null,
                FlowTypeEnum::OAuth2AuthorizationCode,
            ],
            'a token a refresh narrowed to scopes without openid' => [['email'], null],
            'a token of an OpenID Connect code without openid' => [['email'], FlowTypeEnum::OidcAuthorizationCode],
        ];
    }


    /**
     * The endpoint answers for an access token obtained by an OpenID Connect request (OpenID Connect Core 1.0
     * section 5.3), one granted the openid scope. Any other is refused as RFC 6750 section 3.1 has it, with a 403
     * and the challenge naming the error, before the user is looked up. The refusal carries the CORS headers, so
     * that a JavaScript client can read it.
     *
     * @param string[]|null $scopes
     */
    #[DataProvider('tokenWithoutTheOpenIdScopeProvider')]
    public function testRefusesATokenWithoutTheOpenIdScope(?array $scopes, ?FlowTypeEnum $flowType): void
    {
        $this->userRepositoryMock->expects($this->never())->method('getUserEntityByIdentifier');

        $response = $this->userInfoResponseFor($scopes, $flowType, 'Bearer');

        $this->assertSame(403, $response->getStatusCode());
        $this->assertSame(
            'Bearer error="insufficient_scope", DPoP algs="ES256"',
            $response->headers->get('WWW-Authenticate'),
        );
        $this->assertSame('*', $response->headers->get('Access-Control-Allow-Origin'));
        $this->assertSame('WWW-Authenticate', $response->headers->get('Access-Control-Expose-Headers'));

        $body = json_decode((string)$response->getContent(), true, 512, JSON_THROW_ON_ERROR);

        $this->assertIsArray($body);
        $this->assertSame('insufficient_scope', $body['error']);
    }


    /**
     * A token presented under the DPoP scheme is refused under it alone, naming the algorithms a proof may be
     * signed with (RFC 9449 section 7.1).
     */
    public function testRefusesATokenWithoutTheOpenIdScopeUnderTheSchemeItCameUnder(): void
    {
        $response = $this->userInfoResponseFor(['email'], FlowTypeEnum::OAuth2AuthorizationCode, 'DPoP');

        $this->assertSame(403, $response->getStatusCode());
        $this->assertSame(
            'DPoP error="insufficient_scope", algs="ES256"',
            $response->headers->get('WWW-Authenticate'),
        );
    }


    /**
     * @return array<string, array{0: \SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum}>
     */
    public static function credentialFlowProvider(): array
    {
        return [
            'the authorization code flow' => [FlowTypeEnum::VciAuthorizationCode],
            'the pre-authorized code flow' => [FlowTypeEnum::VciPreAuthorizedCode],
        ];
    }


    /**
     * A token of an OpenID4VCI flow need not carry the openid scope, and is answered as before.
     */
    #[DataProvider('credentialFlowProvider')]
    public function testAnswersATokenOfACredentialFlowWithoutTheOpenIdScope(FlowTypeEnum $flowType): void
    {
        $response = $this->userInfoResponseFor(['ResearchCredential'], $flowType, 'Bearer');

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame(
            ['email' => 'userid@localhost.localdomain', 'sub' => 'the-subject'],
            json_decode((string)$response->getContent(), true, 512, JSON_THROW_ON_ERROR),
        );
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

        $this->assertSame('*', $response->headers->get('Access-Control-Allow-Origin'));
        $this->assertSame('WWW-Authenticate', $response->headers->get('Access-Control-Expose-Headers'));
    }
}
