<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Utils;

use Closure;
use DateInterval;
use InvalidArgumentException;
use Jose\Component\KeyManagement\JWKFactory;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Cache\CacheItemInterface;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Exceptions\AuthorizationException;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Helpers\DateTime;
use SimpleSAML\Module\oidc\Helpers\Jwks;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Server\Validators\ClientAttestationVerifier;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\AuthenticatedOAuth2ClientResolver;
use SimpleSAML\Module\oidc\Utils\JwksResolver;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\Module\oidc\ValueAbstracts\PresentedClientAttestation;
use SimpleSAML\Module\oidc\ValueAbstracts\ResolvedClientAuthenticationMethod;
use SimpleSAML\OpenID\Codebooks\ClientAssertionTypesEnum;
use SimpleSAML\OpenID\Codebooks\ClientAuthenticationMethodsEnum;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;
use SimpleSAML\OpenID\Core\ClientAssertion;
use SimpleSAML\OpenID\Exceptions\JwsException;
use SimpleSAML\OpenID\OAuth2;
use SimpleSAML\OpenID\OAuth2\ClientAttestation;
use SimpleSAML\OpenID\OAuth2\ClientAttestationPop;
use SimpleSAML\OpenID\X509;
use SimpleSAML\Test\Module\oidc\unit\Server\Validators\ClientAttestationBuilder;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\Cache\Adapter\AdapterInterface;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Cache\Adapter\ChainAdapter;
use Symfony\Component\Cache\Adapter\NullAdapter;
use Symfony\Component\Cache\Psr16Cache;
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

    protected bool $protocolCacheKeptAcrossRequests = true;

    protected MockObject $clientAttestationVerifierMock;

    /** Whether the verifier mock says the request presents a Client Attestation. */
    protected bool $presentsClientAttestation = false;

    /** A real verifier, for the tests with real attestations; the mock otherwise. */
    protected ?ClientAttestationVerifier $clientAttestationVerifier = null;

    protected bool $isVciEnabled = true;


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
        $this->moduleConfigMock->method('isProtocolCacheKeptAcrossRequests')
            ->willReturnCallback(fn(): bool => $this->protocolCacheKeptAcrossRequests);
        $this->moduleConfigMock->method('getTimestampValidationLeeway')->willReturn(new DateInterval('PT1M'));
        $this->moduleConfigMock->method('getVciEnabled')->willReturnCallback(fn(): bool => $this->isVciEnabled);
        $this->moduleConfigMock->method('getClientAttestationSigningAlgorithms')->willReturn(['ES256', 'ES384']);
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
        $this->helpersMock->method('jwks')->willReturn(new Jwks());
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

        $this->clientAttestationVerifierMock = $this->createMock(ClientAttestationVerifier::class);
        $this->clientAttestationVerifierMock->method('presentsClientAttestation')
            ->willReturnCallback(fn(): bool => $this->presentsClientAttestation);
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
            $this->clientAttestationVerifier ?? $this->clientAttestationVerifierMock,
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


    /**
     * RFC 6749 section 2.3.1: the client ID and the secret are each form-urlencoded before they are joined, so a
     * colon in either travels as `%3A` and the split at the first colon falls between them.
     */
    public function testForClientSecretBasicDecodesFormUrlencodedCredentials(): void
    {
        $clientId = 'urn:example:client';
        $clientSecret = 'a+b/c=d%41:e f';
        $client = $this->confidentialClient($clientId, $clientSecret);
        $this->serverRequestMock->method('getHeader')->with('Authorization')
            ->willReturn(['Basic ' . base64_encode(urlencode($clientId) . ':' . urlencode($clientSecret))]);
        $this->clientRepositoryMock->expects($this->once())->method('findById')
            ->with($clientId)->willReturn($client);

        $result = $this->sut()->forClientSecretBasic($this->serverRequestMock);

        $this->assertInstanceOf(ResolvedClientAuthenticationMethod::class, $result);
        $this->assertSame($client, $result->getClient());
        $this->assertSame(
            ClientAuthenticationMethodsEnum::ClientSecretBasic,
            $result->getClientAuthenticationMethod(),
        );
    }


    /**
     * A client which does not encode, and whose secret decoding would change - a `+` would become a space, `%41`
     * an `A` - is refused on the decoded pair and authenticated on the pair as it sent it.
     */
    public function testForClientSecretBasicTakesCredentialsSentWithoutEncoding(): void
    {
        $clientSecret = 'a+b/c=d%41:e';
        $client = $this->confidentialClient(self::CLIENT_ID, $clientSecret);
        $this->serverRequestMock->method('getHeader')->with('Authorization')
            ->willReturn(['Basic ' . base64_encode(self::CLIENT_ID . ':' . $clientSecret)]);
        $this->clientRepositoryMock->expects($this->exactly(2))->method('findById')
            ->with(self::CLIENT_ID)->willReturn($client);

        $result = $this->sut()->forClientSecretBasic($this->serverRequestMock);

        $this->assertInstanceOf(ResolvedClientAuthenticationMethod::class, $result);
        $this->assertSame($client, $result->getClient());
    }


    /**
     * The same for a client ID, where the client is already known from the request: the decoded ID is not the
     * client's, the ID as sent is.
     */
    public function testForClientSecretBasicTakesAnIdSentWithoutEncodingForAPreFetchedClient(): void
    {
        $clientId = 'client+one%41';
        $client = $this->confidentialClient($clientId, self::CLIENT_SECRET);
        $this->serverRequestMock->method('getHeader')->with('Authorization')
            ->willReturn(['Basic ' . base64_encode($clientId . ':' . self::CLIENT_SECRET)]);
        $this->clientRepositoryMock->expects($this->never())->method('findById');

        $result = $this->sut()->forClientSecretBasic($this->serverRequestMock, $client);

        $this->assertInstanceOf(ResolvedClientAuthenticationMethod::class, $result);
        $this->assertSame($client, $result->getClient());
    }


    public function testForClientSecretBasicRefusesWhenNeitherTheDecodedNorTheSentPairAuthenticates(): void
    {
        $client = $this->confidentialClient(self::CLIENT_ID, self::CLIENT_SECRET);
        $this->serverRequestMock->method('getHeader')->with('Authorization')
            ->willReturn(['Basic ' . base64_encode(self::CLIENT_ID . ':wrong+secret')]);
        $this->clientRepositoryMock->expects($this->exactly(2))->method('findById')
            ->with(self::CLIENT_ID)->willReturn($client);

        $this->expectException(AuthorizationException::class);
        $this->expectExceptionMessage(
            'Basic auth credentials refused, form-urldecoded (Client secret is not valid.) and as sent ' .
            '(Client secret is not valid.).',
        );

        $this->sut()->forClientSecretBasic($this->serverRequestMock);
    }


    /**
     * Credentials which decoding leaves as they are make one pair, and it is tried once.
     */
    public function testForClientSecretBasicTriesCredentialsWhichDecodingLeavesUnchangedOnce(): void
    {
        $client = $this->confidentialClient(self::CLIENT_ID, self::CLIENT_SECRET);
        $this->serverRequestMock->method('getHeader')->with('Authorization')
            ->willReturn(['Basic ' . base64_encode(self::CLIENT_ID . ':wrong-secret')]);
        $this->clientRepositoryMock->expects($this->once())->method('findById')
            ->with(self::CLIENT_ID)->willReturn($client);

        $this->expectException(AuthorizationException::class);
        $this->expectExceptionMessage('Client secret is not valid.');

        $this->sut()->forClientSecretBasic($this->serverRequestMock);
    }


    /**
     * A failure of the OP's own while the decoded pair is tried is no refusal of it, so the pair as sent is not
     * tried after it, and the failure comes out as itself.
     */
    public function testForClientSecretBasicDoesNotTryTheSentPairAfterAFailureOfTheOp(): void
    {
        $this->serverRequestMock->method('getHeader')->with('Authorization')
            ->willReturn(['Basic ' . base64_encode(self::CLIENT_ID . ':some+secret')]);
        $databaseFailure = new RuntimeException('Database error: SQLSTATE[HY000] [2002] Connection refused');
        $this->clientRepositoryMock->expects($this->once())->method('findById')
            ->willThrowException($databaseFailure);

        $this->expectExceptionObject($databaseFailure);

        $this->sut()->forClientSecretBasic($this->serverRequestMock);
    }


    /**
     * A client ID which decoding changes, sent as it is: the decoded ID names no client, the ID as sent does.
     */
    public function testForClientSecretBasicTakesAnIdSentWithoutEncoding(): void
    {
        $clientId = 'client+one';
        $client = $this->confidentialClient($clientId, self::CLIENT_SECRET);
        $this->serverRequestMock->method('getHeader')->with('Authorization')
            ->willReturn(['Basic ' . base64_encode($clientId . ':' . self::CLIENT_SECRET)]);
        $this->clientRepositoryMock->expects($this->exactly(2))->method('findById')
            ->willReturnMap([['client one', null, null], [$clientId, null, $client]]);

        $result = $this->sut()->forClientSecretBasic($this->serverRequestMock);

        $this->assertInstanceOf(ResolvedClientAuthenticationMethod::class, $result);
        $this->assertSame($client, $result->getClient());
    }


    /**
     * A decoded pair which names a client registered for another method is refused like any other, so the pair
     * as sent is tried after it, and the client it names, registered for client_secret_basic, is the one
     * authenticated. The two share a secret here only so that the decoded pair gets as far as the method check.
     */
    public function testForClientSecretBasicTriesTheSentPairWhenTheDecodedOneNamesAClientOfAnotherMethod(): void
    {
        $clientOfPost = $this->confidentialClient('clientA', self::CLIENT_SECRET, 'client_secret_post');
        $clientOfBasic = $this->confidentialClient('client%41', self::CLIENT_SECRET, 'client_secret_basic');
        $this->serverRequestMock->method('getHeader')->with('Authorization')
            ->willReturn(['Basic ' . base64_encode('client%41:' . self::CLIENT_SECRET)]);
        $this->clientRepositoryMock->method('findById')
            ->willReturnMap([['clientA', null, $clientOfPost], ['client%41', null, $clientOfBasic]]);

        $result = $this->sut()->forClientSecretBasic($this->serverRequestMock);

        $this->assertInstanceOf(ResolvedClientAuthenticationMethod::class, $result);
        $this->assertSame($clientOfBasic, $result->getClient());
    }


    /**
     * RFC 6749 Appendix B has the decoded octets taken as UTF-8, so a pair which decodes to anything else was not
     * form-urlencoded, and only the pair as sent is tried. An ID which decodes to one with a NUL is not looked up
     * either: PostgreSQL refuses to compare one, and the request would fail instead of the pair being refused.
     */
    #[DataProvider('credentialsWhichDoNotDecodeToAPairProvider')]
    public function testForClientSecretBasicTriesOnlyTheSentPairWhenTheDecodedOneCanNotBeAPair(
        string $clientId,
        string $clientSecret,
    ): void {
        $client = $this->confidentialClient($clientId, $clientSecret);
        $this->serverRequestMock->method('getHeader')->with('Authorization')
            ->willReturn(['Basic ' . base64_encode($clientId . ':' . $clientSecret)]);
        $this->clientRepositoryMock->expects($this->once())->method('findById')
            ->with($clientId)->willReturn($client);

        $result = $this->sut()->forClientSecretBasic($this->serverRequestMock);

        $this->assertInstanceOf(ResolvedClientAuthenticationMethod::class, $result);
        $this->assertSame($client, $result->getClient());
    }


    /**
     * @return array<string, array{string, string}>
     */
    public static function credentialsWhichDoNotDecodeToAPairProvider(): array
    {
        return [
            'an ID which decodes to one that is not UTF-8' => ['client%FF', self::CLIENT_SECRET],
            'a secret which decodes to one that is not UTF-8' => [self::CLIENT_ID, 'secret+%C3%28'],
            'an ID which decodes to one with a NUL' => ['client%00', self::CLIENT_SECRET],
        ];
    }


    /**
     * An enabled, confidential client of the given ID and secret, and of the given registered method, if any. The
     * shared client mock's ID is fixed.
     */
    protected function confidentialClient(
        string $clientId,
        string $clientSecret,
        ?string $tokenEndpointAuthMethod = null,
    ): Stub&ClientEntityInterface {
        $client = $this->createStub(ClientEntityInterface::class);
        $client->method('getIdentifier')->willReturn($clientId);
        $client->method('getSecret')->willReturn($clientSecret);
        $client->method('isEnabled')->willReturn(true);
        $client->method('isExpired')->willReturn(false);
        $client->method('isConfidential')->willReturn(true);
        $client->method('getTokenEndpointAuthMethod')->willReturn($tokenEndpointAuthMethod);

        return $client;
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
        $protocolCacheMock->method('has')->willReturnOnConsecutiveCalls(false, true);
        $protocolCacheMock->expects($this->once())->method('set')
            ->with('unique-jti-value', 61, 'client_assertion_jti', 'unique-jti-value')
            ->willReturn(true);

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


    /**
     * An assertion which verifies only with an RSA key of the client shorter than 2048 bits (FAPI 2.0 section 5.4.1)
     * is told apart, by verifying it again without the short keys; one a longer key made is not, and a key set
     * without short keys is verified once.
     *
     * @param list<array<string,string>> $keys
     * @param list<list<string>> $verifiedWith
     */
    #[DataProvider('assertionSigningKeyProvider')]
    public function testForPrivateKeyJwtTellsWhetherTheAssertionIsSignedWithAShortRsaKey(
        array $keys,
        string $signingKeyId,
        bool $isSignedWithAShortRsaKey,
        array $verifiedWith,
    ): void {
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnOnConsecutiveCalls('some-assertion-token', ClientAssertionTypesEnum::JwtBaerer->value);
        $this->requestParamsResolverMock->method('parseClientAssertionToken')
            ->willReturn($this->clientAssertionMock);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);
        $this->jwksResolverMock->method('forClient')->willReturn(['keys' => $keys]);
        $this->dateTimeHelperMock->method('getSecondsToExpirationTime')->willReturn(60);
        $verifications = [];
        $this->clientAssertionMock->method('verifyWithKeySet')->willReturnCallback(
            static function (array $jwks) use ($signingKeyId, &$verifications): void {
                /** @var array{keys: list<array<string,string>>} $jwks */
                $keyIds = array_column($jwks['keys'], 'kid');
                $verifications[] = $keyIds;

                if (!in_array($signingKeyId, $keyIds, true)) {
                    throw new JwsException('Could not verify JWS signature.');
                }
            },
        );

        $result = $this->sut()->forPrivateKeyJwt($this->serverRequestMock);

        $this->assertInstanceOf(ResolvedClientAuthenticationMethod::class, $result);
        $this->assertSame($isSignedWithAShortRsaKey, $result->isSignedWithAShortRsaKey());
        $this->assertSame($verifiedWith, $verifications);
    }


    public static function assertionSigningKeyProvider(): array
    {
        $short = self::rsaJwk(2047, 'short');
        $long = self::rsaJwk(2048, 'long');
        $ec = ['kty' => 'EC', 'kid' => 'ec', 'crv' => 'P-256', 'x' => 'x', 'y' => 'y'];
        $verifiedTwice = [['short', 'long'], ['long']];

        return [
            'signed with a short key beside a long one' => [[$short, $long], 'short', true, $verifiedTwice],
            'signed with a long key beside a short one' => [[$short, $long], 'long', false, $verifiedTwice],
            'signed with the only key, a short one' => [[$short], 'short', true, [['short'], []]],
            'no short key' => [[$long, $ec], 'ec', false, [['long', 'ec']]],
        ];
    }


    /**
     * A public RSA key whose modulus has the given length: its most significant bit followed by ones. Only the length
     * is read.
     *
     * @return array<string,string>
     */
    protected static function rsaJwk(int $modulusBits, string $keyId): array
    {
        $octets = intdiv($modulusBits + 7, 8);
        $modulus = chr(1 << ($modulusBits - ($octets - 1) * 8 - 1)) . str_repeat("\xFF", $octets - 1);

        return [
            'kty' => 'RSA',
            'kid' => $keyId,
            'n' => rtrim(strtr(base64_encode($modulus), '+/', '-_'), '='),
            'e' => 'AQAB',
        ];
    }


    /**
     * The assertion is a credential until it expires, and without a protocol cache nothing stops it being
     * replayed, so no log line - debug included - may carry it.
     */
    public function testForPrivateKeyJwtNeverLogsTheAssertion(): void
    {
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnOnConsecutiveCalls('some-assertion-token', ClientAssertionTypesEnum::JwtBaerer->value);
        $this->requestParamsResolverMock->method('parseClientAssertionToken')
            ->willReturn($this->clientAssertionMock);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);
        $this->jwksResolverMock->method('forClient')->willReturn(['keys' => []]);
        $this->dateTimeHelperMock->method('getSecondsToExpirationTime')->willReturn(60);

        $messages = [];
        $contexts = [];
        foreach (['debug', 'info', 'notice', 'warning', 'error'] as $level) {
            $this->loggerServiceMock->method($level)
                ->willReturnCallback(
                    function (string $message, array $context = []) use (&$messages, &$contexts): void {
                        $messages[] = $message;
                        $contexts[] = (string)json_encode($context);
                    },
                );
        }

        $this->sut()->forPrivateKeyJwt($this->serverRequestMock);

        $this->assertContains('Client assertion param received (20 bytes, not logged).', $messages);
        foreach ([...$messages, ...$contexts] as $logged) {
            $this->assertStringNotContainsString('some-assertion-token', $logged);
        }
    }


    /**
     * The parser accepts an assertion until its expiration time and for the leeway past it (a minute here), so it
     * is remembered as long; one past its expiration time but within the leeway, for what is left of it, and one
     * whose time is up by now, for a second.
     *
     * @return array<string,array{int,int}>
     */
    public static function rememberedForProvider(): array
    {
        return [
            'a minute before it expires' => [60, 120],
            'half a minute after it expired' => [-30, 30],
            'as its leeway runs out' => [-60, 1],
            'past its leeway' => [-90, 1],
        ];
    }


    #[DataProvider('rememberedForProvider')]
    public function testForPrivateKeyJwtRemembersAnAssertionForAsLongAsItIsAccepted(
        int $secondsToExpiration,
        int $ttl,
    ): void {
        $this->arrangeAcceptedClientAssertion($secondsToExpiration);
        $protocolCacheMock = $this->createMock(ProtocolCache::class);
        $protocolCacheMock->method('has')->willReturnOnConsecutiveCalls(false, true);
        $protocolCacheMock->expects($this->once())
            ->method('set')
            ->with('unique-jti-value', $ttl, 'client_assertion_jti', 'unique-jti-value')
            ->willReturn(true);

        $this->sut($protocolCacheMock)->forPrivateKeyJwt($this->serverRequestMock);
    }


    /**
     * Presented again, an assertion is refused: the protocol cache remembers it from the first time.
     */
    public function testForPrivateKeyJwtRefusesAnAssertionPresentedAgain(): void
    {
        $this->arrangeAcceptedClientAssertion();
        $protocolCache = new ProtocolCache(new Psr16Cache(new ArrayAdapter()));

        $this->assertInstanceOf(
            ResolvedClientAuthenticationMethod::class,
            $this->sut($protocolCache)->forPrivateKeyJwt($this->serverRequestMock),
        );

        $this->expectException(AuthorizationException::class);
        $this->expectExceptionMessage('Client Assertion reused');

        $this->sut($protocolCache)->forPrivateKeyJwt($this->serverRequestMock);
    }


    /**
     * @return array<string,array{\Symfony\Component\Cache\Adapter\AdapterInterface}>
     */
    public static function cacheWhichDoesNotKeepTheAssertionProvider(): array
    {
        return [
            'writes failing' => [self::adapterWhoseWritesFail()],
            'a chained backend whose writes fail' => [
                new ChainAdapter([new ArrayAdapter(), self::adapterWhoseWritesFail()]),
            ],
            'an adapter which keeps nothing' => [new NullAdapter()],
        ];
    }


    /**
     * Symfony's adapters log a failed write rather than throw, so an assertion whose record the cache did not
     * keep would be accepted again: one adapter reports the write as not done, a chain of adapters reports a
     * write one of its layers lost though a read is answered from another, and an adapter which keeps nothing
     * reports every write as done (named as the protocol cache adapter it turns the check off, but inside an
     * adapter built of others the configuration does not say what it is). The request fails instead, as the
     * OP's own failure rather than a refusal of the client, which the endpoints answer with `server_error`.
     */
    #[DataProvider('cacheWhichDoesNotKeepTheAssertionProvider')]
    public function testForAnySupportedMethodFailsWhenTheCacheDoesNotKeepTheAssertion(AdapterInterface $adapter): void
    {
        $this->arrangeAcceptedClientAssertion();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('the protocol cache did not keep it');

        $this->sut(new ProtocolCache(new Psr16Cache($adapter)))->forAnySupportedMethod($this->serverRequestMock);
    }


    /**
     * In a protocol cache which keeps nothing from one request to the next an assertion remembered here would be
     * forgotten by the next request, so the cache is not asked, as when there is none, and the debug log says so.
     */
    public function testForPrivateKeyJwtChecksNoReuseInACacheWhichKeepsNothingAcrossRequests(): void
    {
        $this->arrangeAcceptedClientAssertion();
        $this->protocolCacheKeptAcrossRequests = false;
        $protocolCacheMock = $this->createMock(ProtocolCache::class);
        $protocolCacheMock->expects($this->never())->method('has');
        $protocolCacheMock->expects($this->never())->method('set');
        $messages = [];
        $this->loggerServiceMock->method('debug')
            ->willReturnCallback(function (string $message) use (&$messages): void {
                $messages[] = $message;
            });

        $this->assertInstanceOf(
            ResolvedClientAuthenticationMethod::class,
            $this->sut($protocolCacheMock)->forPrivateKeyJwt($this->serverRequestMock),
        );
        $this->assertContains(
            'Client assertions are not checked for reuse, since no protocol cache which keeps entries across ' .
            'requests is configured.',
            $messages,
        );
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


    /**
     * An assertion every check accepts, presented as often as the test asks.
     */
    protected function arrangeAcceptedClientAssertion(int $secondsToExpiration = 60): void
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
        $this->dateTimeHelperMock->method('getSecondsToExpirationTime')->willReturn($secondsToExpiration);
    }


    /**
     * A Symfony adapter whose writes fail the way Symfony's adapters fail them: reported as not done, rather
     * than thrown.
     */
    protected static function adapterWhoseWritesFail(): ArrayAdapter
    {
        return new class extends ArrayAdapter {
            public function save(CacheItemInterface $item): bool
            {
                return false;
            }
        };
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

    // -----------------------------------------------------------------------
    // forClientAttestation
    // -----------------------------------------------------------------------

    protected function presentedAttestation(string $clientId = self::CLIENT_ID): PresentedClientAttestation
    {
        return new PresentedClientAttestation(
            $this->createStub(ClientAttestation::class),
            $this->createStub(ClientAttestationPop::class),
            $clientId,
            time() + 300,
            time(),
            null,
            'pop-1',
            'instance-key-thumbprint',
        );
    }


    /**
     * A request presenting a Client Attestation, and nothing else unless the parameters say so.
     *
     * @param array<string,string> $params
     */
    protected function presentAttestation(array $params = []): PresentedClientAttestation
    {
        $this->presentsClientAttestation = true;
        $this->serverRequestMock->method('getHeader')->with('Authorization')->willReturn([]);
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnCallback(static fn(string $paramKey): ?string => $params[$paramKey] ?? null);

        $presented = $this->presentedAttestation();
        $this->clientAttestationVerifierMock->method('parse')->willReturn($presented);

        return $presented;
    }


    public function testForClientAttestationReturnsNullWhenNoneIsPresented(): void
    {
        $this->clientAttestationVerifierMock->expects($this->never())->method('parse');

        $this->assertNull($this->sut()->forClientAttestation($this->serverRequestMock));
    }


    public function testForClientAttestationResolvesTheClientTheAttestationNames(): void
    {
        $presented = $this->presentAttestation();
        $this->clientRepositoryMock->expects($this->once())->method('findById')->with(self::CLIENT_ID)
            ->willReturn($this->clientEntityMock);
        $this->clientAttestationVerifierMock->expects($this->once())->method('verify')
            ->with($this->identicalTo($presented), $this->identicalTo($this->clientEntityMock));

        $result = $this->sut()->forClientAttestation($this->serverRequestMock);

        $this->assertInstanceOf(ResolvedClientAuthenticationMethod::class, $result);
        $this->assertSame($this->clientEntityMock, $result->getClient());
        $this->assertSame(
            ClientAuthenticationMethodsEnum::AttestJwtClientAuth,
            $result->getClientAuthenticationMethod(),
        );
    }


    /**
     * Section 9 check 13: a client_id sent with the request is the attestation's `sub`, and is checked before the
     * client is looked up.
     */
    public function testForClientAttestationRefusesAClientIdOtherThanTheAttestationsSubject(): void
    {
        $this->presentAttestation([ParamsEnum::ClientId->value => 'other-client']);
        $this->clientRepositoryMock->expects($this->never())->method('findById');
        $this->clientAttestationVerifierMock->expects($this->never())->method('verify');

        $this->expectException(AuthorizationException::class);
        $this->expectExceptionMessage('The client_id parameter does not name the client the Client Attestation names');

        $this->sut()->forClientAttestation($this->serverRequestMock);
    }


    public function testForClientAttestationAcceptsAClientIdWhichIsTheAttestationsSubject(): void
    {
        $this->presentAttestation([ParamsEnum::ClientId->value => self::CLIENT_ID]);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);

        $this->assertSame(
            ClientAuthenticationMethodsEnum::AttestJwtClientAuth,
            $this->sut()->forClientAttestation($this->serverRequestMock)?->getClientAuthenticationMethod(),
        );
    }


    /**
     * A pre-fetched client is compared with the attestation's `sub`, as for the other methods.
     */
    public function testForClientAttestationRefusesAPreFetchedClientTheAttestationDoesNotName(): void
    {
        $this->presentAttestation();
        $otherClient = $this->createMock(ClientEntityInterface::class);
        $otherClient->method('getIdentifier')->willReturn('other-client');
        $this->clientAttestationVerifierMock->expects($this->never())->method('verify');

        $this->expectException(AuthorizationException::class);
        $this->expectExceptionMessage('Client ID does not match.');

        $this->sut()->forClientAttestation($this->serverRequestMock, $otherClient);
    }


    public function testForClientAttestationIsRefusedWhileCredentialIssuanceIsDisabled(): void
    {
        $this->presentAttestation();
        $this->isVciEnabled = false;
        $this->clientAttestationVerifierMock->expects($this->never())->method('parse');

        $this->expectException(AuthorizationException::class);
        $this->expectExceptionMessage('accepted only while credential issuance is enabled');

        $this->sut()->forClientAttestation($this->serverRequestMock);
    }


    /**
     * RFC 6749 section 2.3: one method per request, so an attestation together with a client secret, a client
     * assertion or a Basic Authorization header is refused, whichever would verify.
     *
     * @return array<string,array{array<string,string>, string[]}>
     */
    public static function otherCredentialsProvider(): array
    {
        return [
            'a client secret' => [[ParamsEnum::ClientSecret->value => self::CLIENT_SECRET], []],
            'a client assertion' => [[ParamsEnum::ClientAssertion->value => 'some-assertion-token'], []],
            'a client assertion type' => [
                [ParamsEnum::ClientAssertionType->value => ClientAssertionTypesEnum::JwtBaerer->value],
                [],
            ],
            'a Basic Authorization header' => [
                [],
                ['Basic ' . base64_encode(self::CLIENT_ID . ':' . self::CLIENT_SECRET)],
            ],
        ];
    }


    /**
     * @param array<string,string> $params
     * @param string[] $authorizationHeader
     */
    #[DataProvider('otherCredentialsProvider')]
    public function testForClientAttestationRefusesCredentialsOfAnotherMethodAlongside(
        array $params,
        array $authorizationHeader,
    ): void {
        $this->presentsClientAttestation = true;
        $this->serverRequestMock->method('getHeader')->with('Authorization')->willReturn($authorizationHeader);
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnCallback(static fn(string $paramKey): ?string => $params[$paramKey] ?? null);
        $this->clientAttestationVerifierMock->expects($this->never())->method('parse');

        $this->expectException(AuthorizationException::class);
        $this->expectExceptionMessage('together with the client credentials of another authentication method');

        $this->sut()->forClientAttestation($this->serverRequestMock);
    }


    public function testPresentsClientCredentialsCountsAClientAttestation(): void
    {
        $this->presentsClientAttestation = true;
        $this->serverRequestMock->method('getHeader')->with('Authorization')->willReturn([]);
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')->willReturn(null);

        $this->assertTrue($this->sut()->presentsClientCredentials($this->serverRequestMock));
    }


    /**
     * Tried first: a request with an attestation is judged by it, and one which fails is refused rather than
     * resolved as the public client its client_id names.
     */
    public function testForAnySupportedMethodRefusesAFailedAttestationWithoutFallingThrough(): void
    {
        $this->presentAttestation([ParamsEnum::ClientId->value => self::CLIENT_ID]);
        $this->clientEntityMock->method('isConfidential')->willReturn(false);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);
        $this->clientAttestationVerifierMock->method('verify')
            ->willThrowException(new AuthorizationException('The Client Attestation PoP has been used before.'));
        $this->loggerServiceMock->expects($this->once())->method('warning')
            ->with('Client authentication refused: The Client Attestation PoP has been used before.');

        $this->assertNull($this->sut()->forAnySupportedMethod($this->serverRequestMock));
    }


    public function testForAnySupportedMethodResolvesAnAttestedClient(): void
    {
        $this->presentAttestation();
        $this->clientEntityMock->method('getTokenEndpointAuthMethod')->willReturn('attest_jwt_client_auth');
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);

        $this->assertSame(
            ClientAuthenticationMethodsEnum::AttestJwtClientAuth,
            $this->sut()->forAnySupportedMethod($this->serverRequestMock)?->getClientAuthenticationMethod(),
        );
    }


    /**
     * A cache which can not check the PoP for replay is the OP's own failure, not a refusal.
     */
    public function testForAnySupportedMethodLetsAFailureOfThePopReplayCheckThrough(): void
    {
        $this->presentAttestation();
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);
        $cacheFailure = new RuntimeException('Unable to check the Client Attestation PoP for replay.');
        $this->clientAttestationVerifierMock->method('verify')->willThrowException($cacheFailure);

        $this->expectExceptionObject($cacheFailure);

        $this->sut()->forAnySupportedMethod($this->serverRequestMock);
    }


    /**
     * The resolver and the verifier together, on real attestations: the client the attestation names, registered
     * for attestation, resolves.
     */
    protected function withRealVerifier(ClientAttestationBuilder $builder): void
    {
        $this->clientAttestationVerifier = new ClientAttestationVerifier(
            new OAuth2(supportedAlgorithms: ClientAttestationBuilder::supportedAlgorithms()),
            new X509(),
            $this->moduleConfigMock,
            new ProtocolCache(new Psr16Cache(new ArrayAdapter())),
            $this->loggerServiceMock,
        );
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')->willReturn(null);
        $client = $builder->client();
        $this->clientRepositoryMock->method('findById')->willReturnCallback(
            static fn(string $clientId): ?ClientEntityInterface => $clientId === $client->getIdentifier() ?
            $client :
            null,
        );
    }


    protected function attestedRequest(string $attestation, string $pop): ServerRequestInterface
    {
        return (new ServerRequest('POST', self::TOKEN_ENDPOINT))
            ->withHeader('OAuth-Client-Attestation', $attestation)
            ->withHeader('OAuth-Client-Attestation-PoP', $pop);
    }


    public function testForAnySupportedMethodResolvesARealAttestation(): void
    {
        $builder = new ClientAttestationBuilder();
        $this->withRealVerifier($builder);

        $result = $this->sut()->forAnySupportedMethod(
            $this->attestedRequest($builder->attestation(), $builder->pop(['aud' => self::ISSUER])),
        );

        $this->assertInstanceOf(ResolvedClientAuthenticationMethod::class, $result);
        $this->assertSame(ClientAttestationBuilder::CLIENT_ID, $result->getClient()->getIdentifier());
        $this->assertSame(
            ClientAuthenticationMethodsEnum::AttestJwtClientAuth,
            $result->getClientAuthenticationMethod(),
        );
    }


    /**
     * The conformance suite's six negative cases, which it sends to the pushed authorization request endpoint, each
     * refused on its own as the null the endpoint answers `invalid_client` for.
     *
     * @return array<string,array{\Closure}>
     */
    public static function suiteNegativeCaseProvider(): array
    {
        $aud = ['aud' => self::ISSUER];

        return [
            'an attestation signed by another key' => [
                static fn(ClientAttestationBuilder $b): array => [
                    $b->attestation(signingKey: JWKFactory::createECKey('P-256')),
                    $b->pop($aud),
                ],
            ],
            'an attestation past its exp' => [
                static fn(ClientAttestationBuilder $b): array => [
                    $b->attestation(['iat' => time() - 900, 'nbf' => time() - 900, 'exp' => time() - 120]),
                    $b->pop($aud),
                ],
            ],
            'an attestation without sub' => [
                static fn(ClientAttestationBuilder $b): array => [$b->attestation(['sub' => null]), $b->pop($aud)],
            ],
            'a PoP for another audience' => [
                static fn(ClientAttestationBuilder $b): array => [
                    $b->attestation(),
                    $b->pop(['aud' => 'https://other.example.org']),
                ],
            ],
            'a PoP signed by another key' => [
                static fn(ClientAttestationBuilder $b): array => [
                    $b->attestation(),
                    $b->pop($aud, JWKFactory::createECKey('P-256')),
                ],
            ],
            'a PoP whose signature was tampered with' => [
                static function (ClientAttestationBuilder $b) use ($aud): array {
                    $pop = $b->pop($aud);
                    return [$b->attestation(), substr($pop, 0, -4) . (str_ends_with($pop, 'AAAA') ? 'BBBB' : 'AAAA')];
                },
            ],
        ];
    }


    /**
     * @param \Closure $tokens
     */
    #[DataProvider('suiteNegativeCaseProvider')]
    public function testForAnySupportedMethodRefusesTheSuitesNegativeCases(Closure $tokens): void
    {
        $builder = new ClientAttestationBuilder();
        $this->withRealVerifier($builder);
        [$attestation, $pop] = $tokens($builder);
        $this->loggerServiceMock->expects($this->once())->method('warning')
            ->with($this->stringStartsWith('Client authentication refused: The Client Attestation'));

        $this->assertNull($this->sut()->forAnySupportedMethod($this->attestedRequest($attestation, $pop)));
    }
}
