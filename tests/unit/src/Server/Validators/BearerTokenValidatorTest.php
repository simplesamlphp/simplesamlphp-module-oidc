<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\Validators;

use InvalidArgumentException;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\Validators\BearerTokenValidator;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Exceptions\InvalidValueException;
use SimpleSAML\OpenID\Exceptions\JwsException;
use SimpleSAML\OpenID\Helpers;
use SimpleSAML\OpenID\Jwks;
use SimpleSAML\OpenID\Jws;
use SimpleSAML\OpenID\Jws\Factories\ParsedJwsFactory;
use SimpleSAML\OpenID\Jws\ParsedJws;

/**
 * @covers \SimpleSAML\Module\oidc\Server\Validators\BearerTokenValidator
 */
#[AllowMockObjectsWithoutExpectations]
class BearerTokenValidatorTest extends TestCase
{
    protected MockObject $accessTokenRepositoryMock;

    protected array $accessTokenState;

    protected AccessTokenEntity $accessTokenEntityMock;

    protected string $accessToken;

    protected ClientEntityInterface $clientEntityMock;

    protected ServerRequestInterface $serverRequest;

    protected MockObject $publicKeyMock;

    protected MockObject $moduleConfigMock;

    protected MockObject $jwsMock;

    protected MockObject $jwksMock;

    protected MockObject $loggerServiceMock;

    protected MockObject $parsedJwsFactoryMock;

    protected MockObject $parsedJwsMock;

    protected string $clientId;


    /**
     * @throws \Exception
     */
    public function setUp(): void
    {
        $this->accessTokenRepositoryMock = $this->createMock(AccessTokenRepository::class);
        $this->serverRequest = new ServerRequest('GET', '/');
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getIssuer')->willReturn('issuer123');

        $this->jwsMock = $this->createMock(Jws::class);
        // The real helpers: the "typ" header is compared as a media type through the library's MediaType helper.
        $this->jwsMock->method('helpers')->willReturn(new Helpers());
        $this->jwksMock = $this->createMock(Jwks::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);

        $this->clientEntityMock = $this->createMock(ClientEntity::class);
        $this->clientId = 'clientId';
        $this->clientEntityMock->method('getIdentifier')->willReturn($this->clientId);

        $this->accessTokenState = [
            'id' => 'accessToken123',
            'iss' => 'issuer123',
            'scopes' => '{"openid":"openid","profile":"profile"}',
            'expires_at' => date('Y-m-d H:i:s', time() + 60),
            'user_id' => 'user123',
            'client_id' => $this->clientId,
            'is_revoked' => false,
            'auth_code_id' => 'authCode123',
        ];

        $this->accessTokenEntityMock = $this->createMock(AccessTokenEntity::class);

        $this->accessToken = 'token';

        $this->parsedJwsFactoryMock = $this->createMock(ParsedJwsFactory::class);
        $this->jwsMock->method('parsedJwsFactory')->willReturn($this->parsedJwsFactoryMock);

        $this->parsedJwsMock = $this->createMock(ParsedJws::class);
        $this->parsedJwsMock->method('getJwtId')->willReturn('accessToken123');
        $this->parsedJwsMock->method('getAudience')->willReturn([$this->clientId]);
        $this->parsedJwsMock->method('getIssuer')->willReturn('issuer123');
    }


    protected function sut(
        ?AccessTokenRepository $accessTokenRepository = null,
        ?ModuleConfig $moduleConfig = null,
        ?Jws $jws = null,
        ?Jwks $jwks = null,
        ?LoggerService $loggerService = null,
    ): BearerTokenValidator {
        $accessTokenRepository ??= $this->accessTokenRepositoryMock;
        $moduleConfig ??= $this->moduleConfigMock;
        $jws ??= $this->jwsMock;
        $jwks ??= $this->jwksMock;
        $loggerService ??= $this->loggerServiceMock;

        return new BearerTokenValidator(
            $accessTokenRepository,
            $moduleConfig,
            $jws,
            $jwks,
            $loggerService,
        );
    }


    public function testValidatorThrowsForNonExistentAccessToken()
    {
        $this->expectException(OidcServerException::class);

        $this->sut()->validateAuthorization($this->serverRequest);
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testValidatesForAuthorizationHeader()
    {
        $serverRequest = $this->serverRequest->withAddedHeader('Authorization', 'Bearer ' . $this->accessToken);

        $this->parsedJwsFactoryMock->method('fromToken')
            ->with($this->accessToken)
            ->willReturn($this->parsedJwsMock);

        $validatedServerRequest = $this->sut()->validateAuthorization($serverRequest);

        $this->assertSame(
            $this->accessTokenState['id'],
            $validatedServerRequest->getAttribute('oauth_access_token_id'),
        );
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testValidatesForPostBodyParam()
    {
        $bodyArray = ['access_token' => $this->accessToken];
        $tempStream = (new Psr17Factory())->createStream(http_build_query($bodyArray));

        $serverRequest = $this->serverRequest
            ->withMethod('POST')
            ->withAddedHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withBody($tempStream)
            ->withParsedBody($bodyArray);

        $this->parsedJwsFactoryMock->method('fromToken')
            ->with($this->accessToken)
            ->willReturn($this->parsedJwsMock);

        $validatedServerRequest = $this->sut()->validateAuthorization($serverRequest);

        $this->assertSame(
            $this->accessTokenState['id'],
            $validatedServerRequest->getAttribute('oauth_access_token_id'),
        );
    }


    public function testThrowsForUnparsableAccessToken()
    {
        $serverRequest = $this->serverRequest->withAddedHeader('Authorization', 'Bearer ' . 'invalid');

        $this->parsedJwsFactoryMock->method('fromToken')
            ->with('invalid')
            ->willThrowException(new JwsException('Unparsable'));

        $this->expectException(OidcServerException::class);

        $this->sut()->validateAuthorization($serverRequest);
    }


    /**
     * The library's verifier hands JOSE's own exceptions through for a header it can not work with; the validator
     * refuses such a token as one it could not verify, so a caller can tell the verdict from a failure of its own.
     */
    public function testRefusesATokenTheVerifierCanNotWorkWithAsUnverifiable(): void
    {
        $this->parsedJwsFactoryMock->method('fromToken')
            ->with($this->accessToken)
            ->willReturn($this->parsedJwsMock);
        $this->parsedJwsMock->method('verifyWithKeySet')
            ->willThrowException(new InvalidArgumentException('Unsupported algorithm'));

        $this->expectException(JwsException::class);
        $this->expectExceptionMessage('Access token signature could not be verified: Unsupported algorithm');

        $this->sut()->ensureValidAccessToken($this->accessToken);
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Exception
     */
    public function testThrowsForRevokedAccessToken()
    {
        $this->accessTokenRepositoryMock->method('isAccessTokenRevoked')->willReturn(true);

        $serverRequest = $this->serverRequest->withAddedHeader('Authorization', 'Bearer ' . $this->accessToken);

        $this->parsedJwsFactoryMock->method('fromToken')
            ->with($this->accessToken)
            ->willReturn($this->parsedJwsMock);

        $this->expectException(OidcServerException::class);

        $this->sut()->validateAuthorization($serverRequest);
    }


    public static function acceptedTypHeaderProvider(): array
    {
        return [
            'absent, pre-upgrade token' => [null],
            'at+jwt' => ['at+jwt'],
            'at+JWT, as the RFC 9068 example has it' => ['at+JWT'],
            'application/at+jwt' => ['application/at+jwt'],
            'media types are case-insensitive (RFC 7515 4.1.9)' => ['AT+JWT'],
            'application/AT+JWT' => ['Application/AT+JWT'],
        ];
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    #[DataProvider('acceptedTypHeaderProvider')]
    public function testAcceptsAccessTokenTypHeader(?string $typ): void
    {
        $this->parsedJwsMock->method('hasHeaderClaim')->with('typ')->willReturn(!is_null($typ));
        $this->parsedJwsMock->method('getType')->willReturn($typ);
        $this->parsedJwsFactoryMock->method('fromToken')->willReturn($this->parsedJwsMock);

        $serverRequest = $this->serverRequest->withAddedHeader('Authorization', 'Bearer ' . $this->accessToken);

        $validatedServerRequest = $this->sut()->validateAuthorization($serverRequest);

        $this->assertSame(
            $this->accessTokenState['id'],
            $validatedServerRequest->getAttribute('oauth_access_token_id'),
        );
        // The header value is passed on as found (null for a pre-upgrade token), so that a consumer can tell a
        // token whose 'sub' is the resolved subject from one whose 'sub' is the internal user identifier.
        $this->assertSame($typ, $validatedServerRequest->getAttribute('oauth_access_token_typ'));
    }


    /**
     * The token's 'sub' is passed on under league's name for it.
     */
    public function testPassesTheTokenSubjectOn(): void
    {
        $this->parsedJwsMock->method('getSubject')->willReturn('subject-from-token');
        $this->parsedJwsFactoryMock->method('fromToken')->willReturn($this->parsedJwsMock);

        $serverRequest = $this->serverRequest->withAddedHeader('Authorization', 'Bearer ' . $this->accessToken);

        $this->assertSame(
            'subject-from-token',
            $this->sut()->validateAuthorization($serverRequest)->getAttribute('oauth_user_id'),
        );
    }


    public static function rejectedTypHeaderProvider(): array
    {
        return [
            'plain JWT' => ['JWT'],
            'application/jwt' => ['application/jwt'],
            'logout token' => ['logout+jwt'],
            'other media type tree' => ['text/at+jwt'],
            'at+jwt with a parameter' => ['at+jwt;v=1'],
            'empty' => [''],
        ];
    }


    #[DataProvider('rejectedTypHeaderProvider')]
    public function testRejectsNonAccessTokenTypHeader(string $typ): void
    {
        $this->parsedJwsMock->method('hasHeaderClaim')->with('typ')->willReturn(true);
        $this->parsedJwsMock->method('getType')->willReturn($typ);
        $this->parsedJwsFactoryMock->method('fromToken')->willReturn($this->parsedJwsMock);
        $this->accessTokenRepositoryMock->expects($this->never())->method('isAccessTokenRevoked');

        $serverRequest = $this->serverRequest->withAddedHeader('Authorization', 'Bearer ' . $this->accessToken);

        try {
            $this->sut()->validateAuthorization($serverRequest);
            $this->fail('Expected OidcServerException.');
        } catch (OidcServerException $exception) {
            $this->assertSame('access_denied', $exception->getErrorType());
            $this->assertStringContainsString('typ is not at+jwt', (string)$exception->getHint());
        }
    }


    public function testRejectsExplicitNullTypHeader(): void
    {
        // The parser reports an absent header and an explicit null alike; only the former is a pre-upgrade token.
        $this->parsedJwsMock->method('hasHeaderClaim')->with('typ')->willReturn(true);
        $this->parsedJwsMock->method('getType')->willReturn(null);
        $this->parsedJwsFactoryMock->method('fromToken')->willReturn($this->parsedJwsMock);
        $this->accessTokenRepositoryMock->expects($this->never())->method('isAccessTokenRevoked');

        $serverRequest = $this->serverRequest->withAddedHeader('Authorization', 'Bearer ' . $this->accessToken);

        try {
            $this->sut()->validateAuthorization($serverRequest);
            $this->fail('Expected OidcServerException.');
        } catch (OidcServerException $exception) {
            $this->assertSame('access_denied', $exception->getErrorType());
            $this->assertStringContainsString('typ missing or unexpected type', (string)$exception->getHint());
        }
    }


    public function testRejectsMalformedTypHeader(): void
    {
        $this->parsedJwsMock->method('hasHeaderClaim')->with('typ')->willReturn(true);
        $this->parsedJwsMock->method('getType')
            ->willThrowException(new InvalidValueException('Unexpected typ'));
        $this->parsedJwsFactoryMock->method('fromToken')->willReturn($this->parsedJwsMock);

        $serverRequest = $this->serverRequest->withAddedHeader('Authorization', 'Bearer ' . $this->accessToken);

        try {
            $this->sut()->validateAuthorization($serverRequest);
            $this->fail('Expected OidcServerException.');
        } catch (OidcServerException $exception) {
            $this->assertSame('access_denied', $exception->getErrorType());
            $this->assertStringContainsString('Unexpected typ', (string)$exception->getHint());
        }
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testThrowsForEmptyAccessTokenJti()
    {
        $accessToken = $this->createMock(ParsedJws::class);
        $this->parsedJwsFactoryMock->method('fromToken')
            ->with($this->accessToken)
            ->willReturn($accessToken);

        $serverRequest = $this->serverRequest->withAddedHeader('Authorization', 'Bearer ' . $this->accessToken);

        $this->expectException(OidcServerException::class);

        $this->sut()->validateAuthorization($serverRequest);
    }
}
