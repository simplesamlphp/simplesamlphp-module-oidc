<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Utils;

use InvalidArgumentException;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Exceptions\AuthorizationException;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Helpers\DateTime;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\AuthenticatedOAuth2ClientResolver;
use SimpleSAML\Module\oidc\Utils\JwksResolver;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\Module\oidc\ValueAbstracts\ResolvedClientAuthenticationMethod;
use SimpleSAML\OpenID\Codebooks\ClientAssertionTypesEnum;
use SimpleSAML\OpenID\Codebooks\ClientAuthenticationMethodsEnum;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;
use SimpleSAML\OpenID\Core\ClientAssertion;
use SimpleSAML\OpenID\Exceptions\JwsException;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\HttpFoundation\Request;
use Throwable;
use TypeError;

#[CoversClass(AuthenticatedOAuth2ClientResolver::class)]
#[AllowMockObjectsWithoutExpectations]
class AuthenticatedOAuth2ClientResolverTest extends TestCase
{
    protected const string CLIENT_ID = 'test-client-id';

    protected const string CLIENT_SECRET = 'test-client-secret';

    protected const string TOKEN_ENDPOINT = 'https://example.org/oidc/token.php';

    protected const string ISSUER = 'https://example.org';


    protected MockObject $clientRepositoryMock;

    protected MockObject $requestParamsResolverMock;

    protected MockObject $loggerServiceMock;

    protected MockObject $psrHttpBridgeMock;

    protected MockObject $psrHttpFactoryMock;

    protected MockObject $jwksResolverMock;

    protected MockObject $moduleConfigMock;

    protected MockObject $routesMock;

    protected MockObject $helpersMock;

    protected MockObject $dateTimeHelperMock;

    protected Stub $protocolCacheStub;

    protected MockObject $serverRequestMock;

    protected MockObject $clientEntityMock;

    protected MockObject $clientAssertionMock;


    protected function setUp(): void
    {
        $this->clientRepositoryMock = $this->createMock(ClientRepository::class);
        $this->requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        $this->psrHttpFactoryMock = $this->createMock(PsrHttpFactory::class);
        $this->psrHttpBridgeMock = $this->createMock(PsrHttpBridge::class);
        $this->psrHttpBridgeMock->method('getPsrHttpFactory')->willReturn($this->psrHttpFactoryMock);
        $this->jwksResolverMock = $this->createMock(JwksResolver::class);
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getIssuer')->willReturn(self::ISSUER);
        $this->routesMock = $this->createMock(Routes::class);
        $this->routesMock->method('getModuleUrl')
            ->willReturnMap([
                [RoutesEnum::Token->value, self::TOKEN_ENDPOINT],
                [RoutesEnum::Authorization->value, 'https://example.org/oidc/authorization.php'],
                [RoutesEnum::PushedAuthorizationRequest->value, 'https://example.org/oidc/par'],
                [
                    RoutesEnum::ApiOAuth2TokenIntrospection->value,
                    'https://example.org/oidc/api/oauth2/token-introspection',
                ],
            ]);
        $this->dateTimeHelperMock = $this->createMock(DateTime::class);
        $this->helpersMock = $this->createMock(Helpers::class);
        $this->helpersMock->method('dateTime')->willReturn($this->dateTimeHelperMock);
        $this->protocolCacheStub = $this->createStub(ProtocolCache::class);

        $this->serverRequestMock = $this->createMock(ServerRequestInterface::class);

        $this->clientEntityMock = $this->createMock(ClientEntityInterface::class);
        $this->clientEntityMock->method('getIdentifier')->willReturn(self::CLIENT_ID);
        $this->clientEntityMock->method('isEnabled')->willReturn(true);
        $this->clientEntityMock->method('isExpired')->willReturn(false);

        $this->clientAssertionMock = $this->createMock(ClientAssertion::class);
        $this->clientAssertionMock->method('getIssuer')->willReturn(self::CLIENT_ID);
        $this->clientAssertionMock->method('getSubject')->willReturn(self::CLIENT_ID);
        $this->clientAssertionMock->method('getAudience')->willReturn([self::TOKEN_ENDPOINT]);
        $this->clientAssertionMock->method('getJwtId')->willReturn('unique-jti-value');
        $this->clientAssertionMock->method('getExpirationTime')->willReturn(time() + 60);
    }


    protected function sut(?ProtocolCache $protocolCache = null): AuthenticatedOAuth2ClientResolver
    {
        return new AuthenticatedOAuth2ClientResolver(
            $this->clientRepositoryMock,
            $this->requestParamsResolverMock,
            $this->loggerServiceMock,
            $this->psrHttpBridgeMock,
            $this->jwksResolverMock,
            $this->moduleConfigMock,
            $this->helpersMock,
            $protocolCache,
            $this->routesMock,
        );
    }

    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(AuthenticatedOAuth2ClientResolver::class, $this->sut());
    }

    // -----------------------------------------------------------------------
    // forPublicClient
    // -----------------------------------------------------------------------

    public function testForPublicClientReturnsNullWhenNoClientIdInRequest(): void
    {
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')->willReturn(null);

        $this->assertNull($this->sut()->forPublicClient($this->serverRequestMock, null));
    }


    public function testForPublicClientReturnsNullWhenClientIdIsEmptyString(): void
    {
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')->willReturn('');

        $this->assertNull($this->sut()->forPublicClient($this->serverRequestMock, null));
    }


    public function testForPublicClientThrowsWhenClientIsConfidential(): void
    {
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturn(self::CLIENT_ID);
        $this->clientEntityMock->method('isConfidential')->willReturn(true);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);

        $this->expectException(AuthorizationException::class);

        $this->sut()->forPublicClient($this->serverRequestMock, null);
    }


    public function testForPublicClientThrowsWhenClientNotFound(): void
    {
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturn(self::CLIENT_ID);
        $this->clientRepositoryMock->method('findById')->willReturn(null);

        $this->expectException(AuthorizationException::class);

        $this->sut()->forPublicClient($this->serverRequestMock, null);
    }


    public function testForPublicClientReturnsResolvedResultForPublicClient(): void
    {
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturn(self::CLIENT_ID);
        $this->clientEntityMock->method('isConfidential')->willReturn(false);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);

        $result = $this->sut()->forPublicClient($this->serverRequestMock, null);

        $this->assertInstanceOf(ResolvedClientAuthenticationMethod::class, $result);
        $this->assertSame($this->clientEntityMock, $result->getClient());
        $this->assertSame(ClientAuthenticationMethodsEnum::None, $result->getClientAuthenticationMethod());
    }


    public function testForPublicClientUsesPreFetchedClientWhenProvided(): void
    {
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturn(self::CLIENT_ID);
        $this->clientEntityMock->method('isConfidential')->willReturn(false);
        // Repository must NOT be called when a pre-fetched client is provided.
        $this->clientRepositoryMock->expects($this->never())->method('findById');

        $result = $this->sut()->forPublicClient($this->serverRequestMock, $this->clientEntityMock);

        $this->assertInstanceOf(ResolvedClientAuthenticationMethod::class, $result);
    }

    // -----------------------------------------------------------------------
    // forClientSecretBasic
    // -----------------------------------------------------------------------

    public function testForClientSecretBasicReturnsNullWhenNoAuthorizationHeader(): void
    {
        $this->serverRequestMock->method('getHeader')->with('Authorization')->willReturn([]);

        $this->assertNull($this->sut()->forClientSecretBasic($this->serverRequestMock));
    }


    public function testForClientSecretBasicReturnsNullWhenHeaderIsNotBasic(): void
    {
        $this->serverRequestMock->method('getHeader')->with('Authorization')
            ->willReturn(['Bearer some-token']);

        $this->assertNull($this->sut()->forClientSecretBasic($this->serverRequestMock));
    }


    public function testForClientSecretBasicReturnsNullWhenBase64DecodeFailsStrictMode(): void
    {
        // Characters outside [A-Za-z0-9+/=] are invalid in strict mode.
        $invalidBase64 = 'Basic !!!';
        $this->serverRequestMock->method('getHeader')->with('Authorization')
            ->willReturn([$invalidBase64]);

        $this->assertNull($this->sut()->forClientSecretBasic($this->serverRequestMock));
    }


    public function testForClientSecretBasicReturnsNullWhenDecodedValueHasNoColon(): void
    {
        // Valid base64 of a string with no colon.
        $encoded = 'Basic ' . base64_encode('clientidonly');
        $this->serverRequestMock->method('getHeader')->with('Authorization')
            ->willReturn([$encoded]);

        $this->assertNull($this->sut()->forClientSecretBasic($this->serverRequestMock));
    }


    public function testForClientSecretBasicReturnsNullWhenClientIdIsEmpty(): void
    {
        // Colon present but client ID part is empty: ":secret"
        $encoded = 'Basic ' . base64_encode(':some-secret');
        $this->serverRequestMock->method('getHeader')->with('Authorization')
            ->willReturn([$encoded]);

        $this->assertNull($this->sut()->forClientSecretBasic($this->serverRequestMock));
    }


    public function testForClientSecretBasicThrowsWhenClientIsNotConfidential(): void
    {
        $encoded = 'Basic ' . base64_encode(self::CLIENT_ID . ':' . self::CLIENT_SECRET);
        $this->serverRequestMock->method('getHeader')->with('Authorization')
            ->willReturn([$encoded]);
        $this->clientEntityMock->method('isConfidential')->willReturn(false);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);

        $this->expectException(AuthorizationException::class);

        $this->sut()->forClientSecretBasic($this->serverRequestMock);
    }


    public function testForClientSecretBasicThrowsWhenSecretIsEmpty(): void
    {
        // Colon present but secret part is empty: "clientid:"
        $encoded = 'Basic ' . base64_encode(self::CLIENT_ID . ':');
        $this->serverRequestMock->method('getHeader')->with('Authorization')
            ->willReturn([$encoded]);
        $this->clientEntityMock->method('isConfidential')->willReturn(true);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);

        $this->expectException(AuthorizationException::class);

        $this->sut()->forClientSecretBasic($this->serverRequestMock);
    }


    public function testForClientSecretBasicThrowsWhenSecretIsInvalid(): void
    {
        $encoded = 'Basic ' . base64_encode(self::CLIENT_ID . ':wrong-secret');
        $this->serverRequestMock->method('getHeader')->with('Authorization')
            ->willReturn([$encoded]);
        $this->clientEntityMock->method('isConfidential')->willReturn(true);
        $this->clientEntityMock->method('getSecret')->willReturn(self::CLIENT_SECRET);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);

        $this->expectException(AuthorizationException::class);

        $this->sut()->forClientSecretBasic($this->serverRequestMock);
    }


    /**
     * The scheme name is case-insensitive (RFC 9110, section 11.1), and more than one space may follow it.
     */
    #[DataProvider('basicSchemeSpellingProvider')]
    public function testForClientSecretBasicReturnsResolvedResultOnSuccess(string $schemePrefix): void
    {
        $encoded = $schemePrefix . base64_encode(self::CLIENT_ID . ':' . self::CLIENT_SECRET);
        $this->serverRequestMock->method('getHeader')->with('Authorization')
            ->willReturn([$encoded]);
        $this->clientEntityMock->method('isConfidential')->willReturn(true);
        $this->clientEntityMock->method('getSecret')->willReturn(self::CLIENT_SECRET);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);

        $result = $this->sut()->forClientSecretBasic($this->serverRequestMock);

        $this->assertInstanceOf(ResolvedClientAuthenticationMethod::class, $result);
        $this->assertSame($this->clientEntityMock, $result->getClient());
        $this->assertSame(
            ClientAuthenticationMethodsEnum::ClientSecretBasic,
            $result->getClientAuthenticationMethod(),
        );
    }


    public static function basicSchemeSpellingProvider(): array
    {
        return [
            'Basic' => ['Basic '],
            'basic' => ['basic '],
            'BASIC' => ['BASIC '],
            'Basic followed by two spaces' => ['Basic  '],
        ];
    }


    public function testForClientSecretBasicConvertsSymfonyRequestToPsr(): void
    {
        $symfonyRequest = Request::create('/', 'POST');

        $psrRequest = $this->createMock(ServerRequestInterface::class);
        $psrRequest->method('getHeader')->with('Authorization')->willReturn([]);

        $this->psrHttpFactoryMock->expects($this->once())
            ->method('createRequest')
            ->with($symfonyRequest)
            ->willReturn($psrRequest);

        $result = $this->sut()->forClientSecretBasic($symfonyRequest);

        $this->assertNull($result);
    }

    // -----------------------------------------------------------------------
    // forClientSecretPost
    // -----------------------------------------------------------------------

    public function testForClientSecretPostReturnsNullWhenNoClientIdInPostBody(): void
    {
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturn(null);

        $this->assertNull($this->sut()->forClientSecretPost($this->serverRequestMock));
    }


    public function testForClientSecretPostReturnsNullWhenClientIdIsEmpty(): void
    {
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturn('');

        $this->assertNull($this->sut()->forClientSecretPost($this->serverRequestMock));
    }


    public function testForClientSecretPostThrowsWhenClientIsNotConfidential(): void
    {
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnOnConsecutiveCalls(self::CLIENT_ID, self::CLIENT_SECRET);
        $this->clientEntityMock->method('isConfidential')->willReturn(false);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);

        $this->expectException(AuthorizationException::class);

        $this->sut()->forClientSecretPost($this->serverRequestMock);
    }


    public function testForClientSecretPostReturnsNullWhenSecretIsNull(): void
    {
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnOnConsecutiveCalls(self::CLIENT_ID, null);

        $this->assertNull($this->sut()->forClientSecretPost($this->serverRequestMock));
    }


    public function testForClientSecretPostReturnsNullWhenSecretIsEmpty(): void
    {
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnOnConsecutiveCalls(self::CLIENT_ID, '');

        $this->assertNull($this->sut()->forClientSecretPost($this->serverRequestMock));
    }


    public function testForClientSecretPostThrowsWhenSecretIsInvalid(): void
    {
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnOnConsecutiveCalls(self::CLIENT_ID, 'wrong-secret');
        $this->clientEntityMock->method('isConfidential')->willReturn(true);
        $this->clientEntityMock->method('getSecret')->willReturn(self::CLIENT_SECRET);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);

        $this->expectException(AuthorizationException::class);

        $this->sut()->forClientSecretPost($this->serverRequestMock);
    }


    public function testForClientSecretPostReturnsResolvedResultOnSuccess(): void
    {
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnOnConsecutiveCalls(self::CLIENT_ID, self::CLIENT_SECRET);
        $this->clientEntityMock->method('isConfidential')->willReturn(true);
        $this->clientEntityMock->method('getSecret')->willReturn(self::CLIENT_SECRET);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);

        $result = $this->sut()->forClientSecretPost($this->serverRequestMock);

        $this->assertInstanceOf(ResolvedClientAuthenticationMethod::class, $result);
        $this->assertSame($this->clientEntityMock, $result->getClient());
        $this->assertSame(
            ClientAuthenticationMethodsEnum::ClientSecretPost,
            $result->getClientAuthenticationMethod(),
        );
    }

    // -----------------------------------------------------------------------
    // forPrivateKeyJwt
    // -----------------------------------------------------------------------

    public function testForPrivateKeyJwtReturnsNullWhenNoClientAssertionParam(): void
    {
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturn(null);

        $this->assertNull($this->sut()->forPrivateKeyJwt($this->serverRequestMock));
    }


    public function testForPrivateKeyJwtReturnsNullWhenAssertionTypeIsNotJwtBearer(): void
    {
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnOnConsecutiveCalls('some-assertion-token', 'unexpected_type');

        $this->assertNull($this->sut()->forPrivateKeyJwt($this->serverRequestMock));
    }


    public function testForPrivateKeyJwtThrowsWhenJwksNotAvailable(): void
    {
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnOnConsecutiveCalls('some-assertion-token', ClientAssertionTypesEnum::JwtBaerer->value);
        $this->requestParamsResolverMock->method('parseClientAssertionToken')
            ->willReturn($this->clientAssertionMock);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);
        $this->jwksResolverMock->method('forClient')->willReturn(null);

        $this->expectException(AuthorizationException::class);
        $this->expectExceptionMessage('client JWKS not available');

        $this->sut()->forPrivateKeyJwt($this->serverRequestMock);
    }


    public function testForPrivateKeyJwtThrowsWhenSignatureVerificationFails(): void
    {
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnOnConsecutiveCalls('some-assertion-token', ClientAssertionTypesEnum::JwtBaerer->value);
        $this->requestParamsResolverMock->method('parseClientAssertionToken')
            ->willReturn($this->clientAssertionMock);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);
        $this->jwksResolverMock->method('forClient')->willReturn(['keys' => []]);
        $this->clientAssertionMock->method('verifyWithKeySet')
            ->willThrowException(new JwsException('Signature mismatch'));

        $this->expectException(AuthorizationException::class);
        $this->expectExceptionMessage('Client Assertion validation failed');

        $this->sut()->forPrivateKeyJwt($this->serverRequestMock);
    }


    /**
     * An assertion the parser refuses (malformed, a claim missing, expired) is the client's doing, so it is
     * refused as one, with the parser's exception kept as the cause, rather than let out for
     * forAnySupportedMethod() to mistake for a failure of the OP's own. Parsing reads nothing but the
     * assertion, so that holds whatever the parser throws, the library's exception or a PHP error.
     */
    #[DataProvider('unparsableAssertionProvider')]
    public function testForPrivateKeyJwtRefusesAnAssertionWhichDoesNotParse(Throwable $thrown): void
    {
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnOnConsecutiveCalls('some-assertion-token', ClientAssertionTypesEnum::JwtBaerer->value);
        $this->requestParamsResolverMock->method('parseClientAssertionToken')
            ->willThrowException($thrown);
        $this->clientRepositoryMock->expects($this->never())->method('findById');

        try {
            $this->sut()->forPrivateKeyJwt($this->serverRequestMock);
            $this->fail('An assertion which does not parse was not refused.');
        } catch (AuthorizationException $exception) {
            $this->assertStringContainsString($thrown->getMessage(), $exception->getMessage());
            $this->assertSame($thrown, $exception->getPrevious());
        }
    }


    public static function unparsableAssertionProvider(): array
    {
        return [
            'a token which does not parse' => [new JwsException('Unable to parse token.')],
            'a header the JOSE library chokes on' => [
                new TypeError('AlgorithmManager::get(): Argument #1 ($algorithm) must be of type string'),
            ],
        ];
    }


    /**
     * The same for key material the JWKS resolver cannot make a key set of: a Signed JWKS which does not parse
     * or verify comes out as one of the library's exceptions, key data missing what a key needs as the JWK
     * library's InvalidArgumentException, a Signed JWKS header the JOSE library cannot take as a PHP error. All
     * are the client's registration at fault - the fetcher answers null, not an exception, for a URI it cannot
     * reach - so each is a refusal.
     */
    #[DataProvider('unusableJwksProvider')]
    public function testForPrivateKeyJwtRefusesAnAssertionWhoseClientJwksCannotBeUsed(Throwable $thrown): void
    {
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnOnConsecutiveCalls('some-assertion-token', ClientAssertionTypesEnum::JwtBaerer->value);
        $this->requestParamsResolverMock->method('parseClientAssertionToken')
            ->willReturn($this->clientAssertionMock);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);
        $this->jwksResolverMock->method('forClient')->willThrowException($thrown);
        $this->clientAssertionMock->expects($this->never())->method('verifyWithKeySet');

        try {
            $this->sut()->forPrivateKeyJwt($this->serverRequestMock);
            $this->fail('An assertion whose client JWKS cannot be used was not refused.');
        } catch (AuthorizationException $exception) {
            $this->assertStringContainsString('client JWKS not usable', $exception->getMessage());
            $this->assertSame($thrown, $exception->getPrevious());
        }
    }


    public static function unusableJwksProvider(): array
    {
        return [
            'a Signed JWKS which does not verify' => [new JwsException('Signed JWKS signature is not valid.')],
            'key data without a key type' => [new InvalidArgumentException('The parameter "kty" is mandatory.')],
            'a Signed JWKS whose alg header is an array' => [
                new TypeError('AlgorithmManager::get(): Argument #1 ($algorithm) must be of type string'),
            ],
        ];
    }


    public function testForPrivateKeyJwtThrowsWhenJtiAlreadyUsed(): void
    {
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnOnConsecutiveCalls('some-assertion-token', ClientAssertionTypesEnum::JwtBaerer->value);
        $this->requestParamsResolverMock->method('parseClientAssertionToken')
            ->willReturn($this->clientAssertionMock);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);
        $this->jwksResolverMock->method('forClient')->willReturn(['keys' => []]);

        $protocolCacheMock = $this->createMock(ProtocolCache::class);
        $protocolCacheMock->method('has')
            ->with('client_assertion_jti', 'unique-jti-value')
            ->willReturn(true); // JTI already in cache → replay attempt

        $this->expectException(AuthorizationException::class);
        $this->expectExceptionMessage('Client Assertion reused');

        $this->sut($protocolCacheMock)->forPrivateKeyJwt($this->serverRequestMock);
    }


    public function testForPrivateKeyJwtThrowsWhenIssuerClaimDoesNotMatchClientId(): void
    {
        // The assertion issuer is CLIENT_ID, but we pass a pre-fetched client with a different
        // identifier. resolveClientOrFail will detect the mismatch and throw.
        $mismatchedClient = $this->createMock(ClientEntityInterface::class);
        $mismatchedClient->method('getIdentifier')->willReturn('different-client-id');
        $mismatchedClient->method('isEnabled')->willReturn(true);
        $mismatchedClient->method('isExpired')->willReturn(false);

        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnOnConsecutiveCalls('some-assertion-token', ClientAssertionTypesEnum::JwtBaerer->value);
        $this->requestParamsResolverMock->method('parseClientAssertionToken')
            ->willReturn($this->clientAssertionMock);
        $this->jwksResolverMock->method('forClient')->willReturn(['keys' => []]);

        $this->expectException(AuthorizationException::class);

        // Pass the mismatched client as a pre-fetched client to trigger the ID check.
        $this->sut()->forPrivateKeyJwt($this->serverRequestMock, $mismatchedClient);
    }


    public function testForPrivateKeyJwtThrowsWhenSubjectClaimDoesNotMatchClientId(): void
    {
        $clientAssertionMock = $this->createMock(ClientAssertion::class);
        $clientAssertionMock->method('getIssuer')->willReturn(self::CLIENT_ID);
        $clientAssertionMock->method('getSubject')->willReturn('different-subject');
        $clientAssertionMock->method('getJwtId')->willReturn('unique-jti-value');

        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnOnConsecutiveCalls('some-assertion-token', ClientAssertionTypesEnum::JwtBaerer->value);
        $this->requestParamsResolverMock->method('parseClientAssertionToken')
            ->willReturn($clientAssertionMock);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);
        $this->jwksResolverMock->method('forClient')->willReturn(['keys' => []]);

        $this->expectException(AuthorizationException::class);
        $this->expectExceptionMessage('Subject claim');

        $this->sut()->forPrivateKeyJwt($this->serverRequestMock);
    }


    public function testForPrivateKeyJwtThrowsWhenAudienceClaimDoesNotContainExpectedValue(): void
    {
        $clientAssertionMock = $this->createMock(ClientAssertion::class);
        $clientAssertionMock->method('getIssuer')->willReturn(self::CLIENT_ID);
        $clientAssertionMock->method('getSubject')->willReturn(self::CLIENT_ID);
        $clientAssertionMock->method('getAudience')->willReturn(['https://unrelated-aud.example.org']);
        $clientAssertionMock->method('getJwtId')->willReturn('unique-jti-value');
        $clientAssertionMock->method('getExpirationTime')->willReturn(time() + 60);

        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnOnConsecutiveCalls('some-assertion-token', ClientAssertionTypesEnum::JwtBaerer->value);
        $this->requestParamsResolverMock->method('parseClientAssertionToken')
            ->willReturn($clientAssertionMock);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);
        $this->jwksResolverMock->method('forClient')->willReturn(['keys' => []]);

        $this->expectException(AuthorizationException::class);
        $this->expectExceptionMessage('Audience claim');

        $this->sut()->forPrivateKeyJwt($this->serverRequestMock);
    }


    public function testForPrivateKeyJwtAcceptsPushedAuthorizationRequestEndpointAsAudience(): void
    {
        // RFC 9126 Section 2: to facilitate interoperability, the AS MUST accept its issuer identifier,
        // token endpoint URL, or pushed authorization request endpoint URL as the client-assertion audience.
        $clientAssertionMock = $this->createMock(ClientAssertion::class);
        $clientAssertionMock->method('getIssuer')->willReturn(self::CLIENT_ID);
        $clientAssertionMock->method('getSubject')->willReturn(self::CLIENT_ID);
        $clientAssertionMock->method('getAudience')->willReturn(['https://example.org/oidc/par']);
        $clientAssertionMock->method('getJwtId')->willReturn('unique-jti-value');
        $clientAssertionMock->method('getExpirationTime')->willReturn(time() + 60);

        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnOnConsecutiveCalls('some-assertion-token', ClientAssertionTypesEnum::JwtBaerer->value);
        $this->requestParamsResolverMock->method('parseClientAssertionToken')
            ->willReturn($clientAssertionMock);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);
        $this->jwksResolverMock->method('forClient')->willReturn(['keys' => []]);
        $this->dateTimeHelperMock->method('getSecondsToExpirationTime')->willReturn(60);

        $this->assertInstanceOf(
            ResolvedClientAuthenticationMethod::class,
            $this->sut()->forPrivateKeyJwt($this->serverRequestMock),
        );
    }


    public function testForPrivateKeyJwtAcceptsTokenIntrospectionEndpointAsAudience(): void
    {
        // The introspection endpoint advertises private_key_jwt (RFC 8414), and RFC 7523 section 3 lets the
        // client address the assertion to the endpoint it calls, so that URL is an audience of this OP too.
        $clientAssertionMock = $this->createMock(ClientAssertion::class);
        $clientAssertionMock->method('getIssuer')->willReturn(self::CLIENT_ID);
        $clientAssertionMock->method('getSubject')->willReturn(self::CLIENT_ID);
        $clientAssertionMock->method('getAudience')
            ->willReturn(['https://example.org/oidc/api/oauth2/token-introspection']);
        $clientAssertionMock->method('getJwtId')->willReturn('unique-jti-value');
        $clientAssertionMock->method('getExpirationTime')->willReturn(time() + 60);

        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnOnConsecutiveCalls('some-assertion-token', ClientAssertionTypesEnum::JwtBaerer->value);
        $this->requestParamsResolverMock->method('parseClientAssertionToken')
            ->willReturn($clientAssertionMock);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);
        $this->jwksResolverMock->method('forClient')->willReturn(['keys' => []]);
        $this->dateTimeHelperMock->method('getSecondsToExpirationTime')->willReturn(60);

        $this->assertInstanceOf(
            ResolvedClientAuthenticationMethod::class,
            $this->sut()->forPrivateKeyJwt($this->serverRequestMock),
        );
    }


    public function testForPrivateKeyJwtAcceptsIssuerIdentifierAsAudience(): void
    {
        $clientAssertionMock = $this->createMock(ClientAssertion::class);
        $clientAssertionMock->method('getIssuer')->willReturn(self::CLIENT_ID);
        $clientAssertionMock->method('getSubject')->willReturn(self::CLIENT_ID);
        $clientAssertionMock->method('getAudience')->willReturn([self::ISSUER]);
        $clientAssertionMock->method('getJwtId')->willReturn('unique-jti-value');
        $clientAssertionMock->method('getExpirationTime')->willReturn(time() + 60);

        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnOnConsecutiveCalls('some-assertion-token', ClientAssertionTypesEnum::JwtBaerer->value);
        $this->requestParamsResolverMock->method('parseClientAssertionToken')
            ->willReturn($clientAssertionMock);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);
        $this->jwksResolverMock->method('forClient')->willReturn(['keys' => []]);
        $this->dateTimeHelperMock->method('getSecondsToExpirationTime')->willReturn(60);

        $this->assertInstanceOf(
            ResolvedClientAuthenticationMethod::class,
            $this->sut()->forPrivateKeyJwt($this->serverRequestMock),
        );
    }


    /**
     * An assertion is judged once, when parsed. Its expiration accessor checks the clock on every call, so an
     * assertion which expires while its JWKS is fetched would throw the library's exception from the reuse
     * cache bookkeeping further down, past the conversion into a refusal, and become a server fault. It was
     * valid when judged, so it is accepted, and the cache is given the expiration read at that moment.
     */
    public function testForPrivateKeyJwtAcceptsAnAssertionWhichExpiresAfterItWasJudged(): void
    {
        $expirationTime = time() + 1;
        $expired = false;
        $clientAssertionMock = $this->createMock(ClientAssertion::class);
        $clientAssertionMock->method('getIssuer')->willReturn(self::CLIENT_ID);
        $clientAssertionMock->method('getSubject')->willReturn(self::CLIENT_ID);
        $clientAssertionMock->method('getAudience')->willReturn([self::TOKEN_ENDPOINT]);
        $clientAssertionMock->method('getJwtId')->willReturn('unique-jti-value');
        $clientAssertionMock->method('getExpirationTime')->willReturnCallback(
            static function () use (&$expired, $expirationTime): int {
                if ($expired) {
                    throw new JwsException('Expiration Time claim is lesser than current time.');
                }
                $expired = true;

                return $expirationTime;
            },
        );

        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnOnConsecutiveCalls('some-assertion-token', ClientAssertionTypesEnum::JwtBaerer->value);
        $this->requestParamsResolverMock->method('parseClientAssertionToken')
            ->willReturn($clientAssertionMock);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);
        $this->jwksResolverMock->method('forClient')->willReturn(['keys' => []]);
        $this->dateTimeHelperMock->expects($this->once())->method('getSecondsToExpirationTime')
            ->with($expirationTime)
            ->willReturn(1);
        $protocolCacheMock = $this->createMock(ProtocolCache::class);
        $protocolCacheMock->method('has')->willReturn(false);
        $protocolCacheMock->expects($this->once())->method('set')
            ->with('unique-jti-value', 1, 'client_assertion_jti', 'unique-jti-value');

        $result = $this->sut($protocolCacheMock)->forPrivateKeyJwt($this->serverRequestMock);

        $this->assertInstanceOf(ResolvedClientAuthenticationMethod::class, $result);
        $this->assertSame($this->clientEntityMock, $result->getClient());
    }


    public function testForPrivateKeyJwtReturnsResolvedResultOnSuccess(): void
    {
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnOnConsecutiveCalls('some-assertion-token', ClientAssertionTypesEnum::JwtBaerer->value);
        $this->requestParamsResolverMock->method('parseClientAssertionToken')
            ->willReturn($this->clientAssertionMock);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);
        $this->jwksResolverMock->method('forClient')->willReturn(['keys' => []]);
        $this->dateTimeHelperMock->method('getSecondsToExpirationTime')->willReturn(60);

        $result = $this->sut()->forPrivateKeyJwt($this->serverRequestMock);

        $this->assertInstanceOf(ResolvedClientAuthenticationMethod::class, $result);
        $this->assertSame($this->clientEntityMock, $result->getClient());
        $this->assertSame(
            ClientAuthenticationMethodsEnum::PrivateKeyJwt,
            $result->getClientAuthenticationMethod(),
        );
    }


    public function testForPrivateKeyJwtStoresJtiInCacheAfterSuccess(): void
    {
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnOnConsecutiveCalls('some-assertion-token', ClientAssertionTypesEnum::JwtBaerer->value);
        $this->requestParamsResolverMock->method('parseClientAssertionToken')
            ->willReturn($this->clientAssertionMock);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);
        $this->jwksResolverMock->method('forClient')->willReturn(['keys' => []]);
        $this->dateTimeHelperMock->method('getSecondsToExpirationTime')->willReturn(60);

        $protocolCacheMock = $this->createMock(ProtocolCache::class);
        $protocolCacheMock->method('has')->willReturn(false);
        $protocolCacheMock->expects($this->once())
            ->method('set')
            ->with(
                'unique-jti-value',
                60,
                'client_assertion_jti',
                'unique-jti-value',
            );

        $this->sut($protocolCacheMock)->forPrivateKeyJwt($this->serverRequestMock);
    }


    public function testForPrivateKeyJwtSkipsJtiCheckWhenNoCacheProvided(): void
    {
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnOnConsecutiveCalls('some-assertion-token', ClientAssertionTypesEnum::JwtBaerer->value);
        $this->requestParamsResolverMock->method('parseClientAssertionToken')
            ->willReturn($this->clientAssertionMock);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);
        $this->jwksResolverMock->method('forClient')->willReturn(['keys' => []]);
        $this->dateTimeHelperMock->method('getSecondsToExpirationTime')->willReturn(60);

        // No cache passed — must succeed without any replay check.
        $result = $this->sut(null)->forPrivateKeyJwt($this->serverRequestMock);

        $this->assertInstanceOf(ResolvedClientAuthenticationMethod::class, $result);
    }

    // -----------------------------------------------------------------------
    // forAnySupportedMethod
    // -----------------------------------------------------------------------

    public function testForAnySupportedMethodReturnsNullWhenNoMethodMatches(): void
    {
        // All four methods return null (no matching credentials anywhere).
        $this->serverRequestMock->method('getHeader')->with('Authorization')->willReturn([]);
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')->willReturn(null);

        $this->assertNull($this->sut()->forAnySupportedMethod($this->serverRequestMock));
    }


    /**
     * A refusal by one of the methods - here a wrong secret - is the null answer, logged with its reason as
     * the client failure it is, not as an error of the OP's.
     */
    public function testForAnySupportedMethodAnswersNullForARefusalAndLogsItsReason(): void
    {
        $this->serverRequestMock->method('getHeader')->with('Authorization')
            ->willReturn(['Basic ' . base64_encode(self::CLIENT_ID . ':wrong-secret')]);
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')->willReturn(null);
        $this->clientEntityMock->method('isConfidential')->willReturn(true);
        $this->clientEntityMock->method('getSecret')->willReturn(self::CLIENT_SECRET);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);
        $this->loggerServiceMock->expects($this->once())->method('warning')
            ->with($this->stringContains('Client secret is not valid'));
        $this->loggerServiceMock->expects($this->never())->method('error');

        $this->assertNull($this->sut()->forAnySupportedMethod($this->serverRequestMock));
    }


    /**
     * A failure of the OP's own is no verdict on the client and is not turned into one: the client lookup
     * failing - the database did not answer - comes out as the exception it was, for the endpoint to answer
     * as `server_error`, instead of as the null which would have the client told its credentials are wrong.
     */
    public function testForAnySupportedMethodLetsAFailureOfTheClientLookupThrough(): void
    {
        $this->serverRequestMock->method('getHeader')->with('Authorization')
            ->willReturn(['Basic ' . base64_encode(self::CLIENT_ID . ':' . self::CLIENT_SECRET)]);
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')->willReturn(null);
        $databaseFailure = new RuntimeException('Database error: SQLSTATE[HY000] [2002] Connection refused');
        $this->clientRepositoryMock->method('findById')->willThrowException($databaseFailure);

        $this->expectExceptionObject($databaseFailure);

        $this->sut()->forAnySupportedMethod($this->serverRequestMock);
    }


    /**
     * The same for the assertion reuse check: a cache which cannot say whether the `jti` was seen before is
     * not a refusal either, and not a pass.
     */
    public function testForAnySupportedMethodLetsAFailureOfTheReuseCheckThrough(): void
    {
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnCallback(static fn(string $paramKey): ?string => match ($paramKey) {
                ParamsEnum::ClientAssertion->value => 'some-assertion-token',
                ParamsEnum::ClientAssertionType->value => ClientAssertionTypesEnum::JwtBaerer->value,
                default => null,
            });
        $this->requestParamsResolverMock->method('parseClientAssertionToken')
            ->willReturn($this->clientAssertionMock);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);
        $this->jwksResolverMock->method('forClient')->willReturn(['keys' => []]);
        $cacheFailure = new RuntimeException('Cache backend unavailable.');
        $protocolCacheMock = $this->createMock(ProtocolCache::class);
        $protocolCacheMock->method('has')->willThrowException($cacheFailure);

        $this->expectExceptionObject($cacheFailure);

        $this->sut($protocolCacheMock)->forAnySupportedMethod($this->serverRequestMock);
    }


    public function testForAnySupportedMethodPrefersPrivateKeyJwtOverOtherMethods(): void
    {
        // private_key_jwt assertion present — should resolve first and win.
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnCallback(function (string $paramKey) {
                if ($paramKey === ParamsEnum::ClientAssertion->value) {
                    return 'some-assertion-token';
                }
                if ($paramKey === ParamsEnum::ClientAssertionType->value) {
                    return ClientAssertionTypesEnum::JwtBaerer->value;
                }
                return null;
            });
        $this->requestParamsResolverMock->method('parseClientAssertionToken')
            ->willReturn($this->clientAssertionMock);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);
        $this->jwksResolverMock->method('forClient')->willReturn(['keys' => []]);
        $this->dateTimeHelperMock->method('getSecondsToExpirationTime')->willReturn(60);

        // forClientSecretBasic will be tried after forPrivateKeyJwt succeeds and short-circuits,
        // so getHeader should never actually be reached. The PSR bridge is never used here
        // because the request is already a ServerRequestInterface.

        $result = $this->sut()->forAnySupportedMethod($this->serverRequestMock);

        $this->assertInstanceOf(ResolvedClientAuthenticationMethod::class, $result);
        $this->assertSame(
            ClientAuthenticationMethodsEnum::PrivateKeyJwt,
            $result->getClientAuthenticationMethod(),
        );
    }


    /**
     * A registered public client identified by its client_id alone resolves as `none`; that is the fallback
     * the credential methods leave to forPublicClient(). Pinned beside the refusal below as its other half:
     * the guard which refuses a `none` resolution reads what the request presented, and this is what keeps
     * it from being widened into refusing `none` outright.
     */
    public function testForAnySupportedMethodFallsBackToThePublicClientWhenNoCredentialsArePresented(): void
    {
        $this->serverRequestMock->method('getHeader')->with('Authorization')->willReturn([]);
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnCallback(
                static fn(string $paramKey): ?string => $paramKey === ParamsEnum::ClientId->value ?
                    self::CLIENT_ID :
                    null,
            );
        $this->clientEntityMock->method('isConfidential')->willReturn(false);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);

        $result = $this->sut()->forAnySupportedMethod($this->serverRequestMock);

        $this->assertInstanceOf(ResolvedClientAuthenticationMethod::class, $result);
        $this->assertSame(ClientAuthenticationMethodsEnum::None, $result->getClientAuthenticationMethod());
    }


    /**
     * The same public client with credentials it could not be authenticated by does not get that fallback:
     * the request tried to authenticate and failed, and is refused rather than let through as `none`. Each
     * shape is one a credential method declines without throwing, which is what would otherwise have handed
     * the request on to forPublicClient().
     */
    #[DataProvider('unusableCredentialsProvider')]
    public function testForAnySupportedMethodRefusesAPublicClientWhoseCredentialsWentUnused(
        array $authorizationHeader,
        array $postParameters,
    ): void {
        $this->serverRequestMock->method('getHeader')->with('Authorization')->willReturn($authorizationHeader);
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnCallback(
                static fn(string $paramKey): ?string => $postParameters[$paramKey] ?? null,
            );
        $this->clientEntityMock->method('isConfidential')->willReturn(false);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);
        $this->loggerServiceMock->expects($this->once())->method('warning')
            ->with($this->stringContains('none of them could be used to authenticate the client'));

        $this->assertNull($this->sut()->forAnySupportedMethod($this->serverRequestMock));
    }


    public static function unusableCredentialsProvider(): array
    {
        $samlBearer = 'urn:ietf:params:oauth:client-assertion-type:saml2-bearer';

        return [
            'a malformed Basic header' => [['Basic !!!'], [ParamsEnum::ClientId->value => self::CLIENT_ID]],
            'a Basic header carrying nothing' => [['Basic '], [ParamsEnum::ClientId->value => self::CLIENT_ID]],
            'a bare Basic scheme' => [['Basic'], [ParamsEnum::ClientId->value => self::CLIENT_ID]],
            'a Basic header without a colon' => [
                ['Basic ' . base64_encode('no-colon-here')],
                [ParamsEnum::ClientId->value => self::CLIENT_ID],
            ],
            'an assertion of an unsupported type' => [
                [],
                [
                    ParamsEnum::ClientId->value => self::CLIENT_ID,
                    ParamsEnum::ClientAssertion->value => 'some-assertion-token',
                    ParamsEnum::ClientAssertionType->value => $samlBearer,
                ],
            ],
            'an assertion type without an assertion' => [
                [],
                [
                    ParamsEnum::ClientId->value => self::CLIENT_ID,
                    ParamsEnum::ClientAssertionType->value => ClientAssertionTypesEnum::JwtBaerer->value,
                ],
            ],
            'an empty assertion without a type' => [
                [],
                [
                    ParamsEnum::ClientId->value => self::CLIENT_ID,
                    ParamsEnum::ClientAssertion->value => '',
                ],
            ],
        ];
    }


    /**
     * The pre-fetched client goes through to every method, and each holds the client the credentials name
     * against it: Basic credentials for one client, with another handed over as pre-fetched, are refused.
     */
    public function testForAnySupportedMethodRefusesCredentialsWhichNameAnotherClientThanThePreFetchedOne(): void
    {
        $preFetchedClient = $this->createMock(ClientEntityInterface::class);
        $preFetchedClient->method('getIdentifier')->willReturn('different-client-id');
        $preFetchedClient->method('isEnabled')->willReturn(true);
        $preFetchedClient->method('isExpired')->willReturn(false);
        $this->serverRequestMock->method('getHeader')->with('Authorization')
            ->willReturn(['Basic ' . base64_encode(self::CLIENT_ID . ':' . self::CLIENT_SECRET)]);
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')->willReturn(null);
        $this->clientRepositoryMock->expects($this->never())->method('findById');
        // Logged where the mismatch is found and again, as the refusal, where the exception is caught.
        $this->loggerServiceMock->expects($this->once())->method('error')
            ->with($this->stringContains('Client ID does not match'));
        $this->loggerServiceMock->expects($this->once())->method('warning')
            ->with($this->stringContains('Client ID does not match'));

        $this->assertNull($this->sut()->forAnySupportedMethod($this->serverRequestMock, $preFetchedClient));
    }

    // -----------------------------------------------------------------------
    // findActiveClient
    // -----------------------------------------------------------------------

    public function testFindActiveClientReturnsNullWhenClientNotFound(): void
    {
        $this->clientRepositoryMock->method('findById')->willReturn(null);

        $this->assertNull($this->sut()->findActiveClient(self::CLIENT_ID));
    }


    public function testFindActiveClientReturnsNullWhenClientIsDisabled(): void
    {
        $disabledClient = $this->createMock(ClientEntityInterface::class);
        $disabledClient->method('getIdentifier')->willReturn(self::CLIENT_ID);
        $disabledClient->method('isEnabled')->willReturn(false);
        $this->clientRepositoryMock->method('findById')->willReturn($disabledClient);

        $this->assertNull($this->sut()->findActiveClient(self::CLIENT_ID));
    }


    public function testFindActiveClientReturnsNullWhenClientIsExpired(): void
    {
        $expiredClient = $this->createMock(ClientEntityInterface::class);
        $expiredClient->method('getIdentifier')->willReturn(self::CLIENT_ID);
        $expiredClient->method('isEnabled')->willReturn(true);
        $expiredClient->method('isExpired')->willReturn(true);
        $this->clientRepositoryMock->method('findById')->willReturn($expiredClient);

        $this->assertNull($this->sut()->findActiveClient(self::CLIENT_ID));
    }


    public function testFindActiveClientReturnsClientWhenActive(): void
    {
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);

        $this->assertSame($this->clientEntityMock, $this->sut()->findActiveClient(self::CLIENT_ID));
    }

    // -----------------------------------------------------------------------
    // findActiveClientOrFail
    // -----------------------------------------------------------------------

    public function testFindActiveClientOrFailThrowsWhenClientNotActive(): void
    {
        $this->clientRepositoryMock->method('findById')->willReturn(null);

        $this->expectException(AuthorizationException::class);

        $this->sut()->findActiveClientOrFail(self::CLIENT_ID);
    }


    public function testFindActiveClientOrFailReturnsClientWhenActive(): void
    {
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);

        $this->assertSame($this->clientEntityMock, $this->sut()->findActiveClientOrFail(self::CLIENT_ID));
    }

    // -----------------------------------------------------------------------
    // validateClientSecret
    // -----------------------------------------------------------------------

    public function testValidateClientSecretThrowsWhenSecretDoesNotMatch(): void
    {
        $this->clientEntityMock->method('getSecret')->willReturn(self::CLIENT_SECRET);

        $this->expectException(AuthorizationException::class);

        $this->sut()->validateClientSecret($this->clientEntityMock, 'wrong-secret');
    }


    public function testValidateClientSecretDoesNotThrowWhenSecretMatches(): void
    {
        $this->clientEntityMock->method('getSecret')->willReturn(self::CLIENT_SECRET);

        // Must not throw.
        $this->sut()->validateClientSecret($this->clientEntityMock, self::CLIENT_SECRET);
        $this->addToAssertionCount(1);
    }

    // -----------------------------------------------------------------------
    // presentsClientCredentials
    // -----------------------------------------------------------------------

    /**
     * What counts is an attempt: an assertion as soon as it is a string, even an empty one which
     * forPrivateKeyJwt() then refuses; an assertion type on its own, which nothing reads; a header on its
     * `Basic ` prefix alone, whether or not forClientSecretBasic() can parse the rest; a client secret only when
     * it is non-empty, since forClientSecretPost() treats an empty one as absent. A bare client_id is not a
     * credential.
     */
    #[DataProvider('presentedCredentialsProvider')]
    public function testPresentsClientCredentialsTellsCredentialsFromIdentification(
        array $postParameters,
        array $authorizationHeader,
        bool $expected,
    ): void {
        $this->serverRequestMock->method('getHeader')->with('Authorization')->willReturn($authorizationHeader);
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnCallback(
                function (
                    string $paramKey,
                    ServerRequestInterface $request,
                    array $allowedMethods,
                ) use ($postParameters): ?string {
                    $this->assertSame($this->serverRequestMock, $request);
                    $this->assertSame([HttpMethodsEnum::POST], $allowedMethods);

                    return $postParameters[$paramKey] ?? null;
                },
            );

        $this->assertSame($expected, $this->sut()->presentsClientCredentials($this->serverRequestMock));
    }


    public static function presentedCredentialsProvider(): array
    {
        $clientId = [ParamsEnum::ClientId->value => self::CLIENT_ID];

        return [
            'nothing but a client_id' => [$clientId, [], false],
            'a client assertion' => [
                $clientId + [ParamsEnum::ClientAssertion->value => 'some-assertion-token'],
                [],
                true,
            ],
            'an empty client assertion, which is presented and then refused' => [
                $clientId + [ParamsEnum::ClientAssertion->value => ''],
                [],
                true,
            ],
            'a client assertion type without an assertion' => [
                $clientId + [
                    ParamsEnum::ClientAssertionType->value => ClientAssertionTypesEnum::JwtBaerer->value,
                ],
                [],
                true,
            ],
            'a Basic Authorization header' => [$clientId, ['Basic ' . base64_encode('id:secret')], true],
            'a Basic Authorization header with the scheme in lower case' => [
                $clientId,
                ['basic ' . base64_encode('id:secret')],
                true,
            ],
            'a Basic Authorization header carrying nothing usable' => [$clientId, ['Basic '], true],
            'a bare Basic scheme, which is what PSR-7 makes of `Basic ` once trimmed' => [
                $clientId,
                ['Basic'],
                true,
            ],
            'a Bearer Authorization header' => [$clientId, ['Bearer some-token'], false],
            'a scheme which merely starts with Basic' => [$clientId, ['Basically nothing'], false],
            'a client secret' => [
                $clientId + [ParamsEnum::ClientSecret->value => self::CLIENT_SECRET],
                [],
                true,
            ],
            'an empty client secret, which is skipped' => [
                $clientId + [ParamsEnum::ClientSecret->value => ''],
                [],
                false,
            ],
        ];
    }


    /**
     * Through a real PSR-7 request rather than a mock, because the implementation trims the header value:
     * `Basic ` is delivered as `Basic`, which a mock preserving the space never shows. A wallet which sent it
     * attempted to authenticate, so it is presented credentials here and, being empty, credentials
     * forClientSecretBasic() then skips - the shape the public-client guard is for.
     */
    public function testABareBasicSchemeSurvivesPsr7TrimmingAsAnEmptyCredential(): void
    {
        $request = new ServerRequest('POST', 'https://example.org/oidc/token', ['Authorization' => 'Basic ']);
        $this->assertSame(['Basic'], $request->getHeader('Authorization'));
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')->willReturn(null);

        $this->assertTrue($this->sut()->presentsClientCredentials($request));
        $this->assertNull($this->sut()->forClientSecretBasic($request));
    }


    public function testPresentsClientCredentialsConvertsSymfonyRequestToPsr(): void
    {
        $symfonyRequest = Request::create('/', 'POST');
        $psrRequest = $this->createMock(ServerRequestInterface::class);
        $psrRequest->method('getHeader')->with('Authorization')->willReturn(['Basic abc']);
        $this->psrHttpFactoryMock->expects($this->once())
            ->method('createRequest')
            ->with($symfonyRequest)
            ->willReturn($psrRequest);
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->with($this->anything(), $this->identicalTo($psrRequest))
            ->willReturn(null);

        $this->assertTrue($this->sut()->presentsClientCredentials($symfonyRequest));
    }
}
