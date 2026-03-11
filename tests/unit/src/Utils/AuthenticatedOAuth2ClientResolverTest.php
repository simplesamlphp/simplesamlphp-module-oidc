<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Utils;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Exceptions\AuthorizationException;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\AuthenticatedOAuth2ClientResolver;
use SimpleSAML\Module\oidc\Utils\JwksResolver;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Module\oidc\ValueAbstracts\ResolvedClientAuthenticationMethod;
use SimpleSAML\OpenID\Codebooks\ClientAssertionTypesEnum;
use SimpleSAML\OpenID\Codebooks\ClientAuthenticationMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;
use SimpleSAML\OpenID\Core\ClientAssertion;
use SimpleSAML\OpenID\Exceptions\JwsException;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\HttpFoundation\Request;

#[CoversClass(AuthenticatedOAuth2ClientResolver::class)]
class AuthenticatedOAuth2ClientResolverTest extends TestCase
{
    protected const CLIENT_ID = 'test-client-id';
    protected const CLIENT_SECRET = 'test-client-secret';
    protected const TOKEN_ENDPOINT = 'https://example.org/oidc/token.php';
    protected const ISSUER = 'https://example.org';

    protected MockObject $clientRepositoryMock;
    protected MockObject $requestParamsResolverMock;
    protected MockObject $loggerServiceMock;
    protected MockObject $psrHttpBridgeMock;
    protected MockObject $psrHttpFactoryMock;
    protected MockObject $jwksResolverMock;
    protected MockObject $moduleConfigMock;
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
        $this->moduleConfigMock->method('getModuleUrl')
            ->willReturnMap([
                [RoutesEnum::Token->value, self::TOKEN_ENDPOINT],
                [RoutesEnum::Authorization->value, 'https://example.org/oidc/authorization.php'],
            ]);
        $this->moduleConfigMock->method('getIssuer')->willReturn(self::ISSUER);
        $this->dateTimeHelperMock = $this->createMock(Helpers\DateTime::class);
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

    public function testForClientSecretBasicReturnsResolvedResultOnSuccess(): void
    {
        $encoded = 'Basic ' . base64_encode(self::CLIENT_ID . ':' . self::CLIENT_SECRET);
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

    public function testForAnySupportedMethodReturnsNullAndLogsErrorOnException(): void
    {
        // Trigger a hard exception to verify the catch-all swallows it and logs.
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willThrowException(new \RuntimeException('Unexpected error'));

        $this->loggerServiceMock->expects($this->once())->method('error');

        $result = $this->sut()->forAnySupportedMethod($this->serverRequestMock);

        $this->assertNull($result);
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
}
