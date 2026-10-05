<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\Validators;

use Exception;
use InvalidArgumentException;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\ServerRequest;
use PDOException;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Exceptions\TokenNotFoundException;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\Validators\BearerTokenValidator;
use SimpleSAML\Module\oidc\Server\Validators\DpopProofVerifier;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\ValueAbstracts\VerifiedDpopProof;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Exceptions\InvalidValueException;
use SimpleSAML\OpenID\Exceptions\JwsException;
use SimpleSAML\OpenID\Helpers;
use SimpleSAML\OpenID\Jwks;
use SimpleSAML\OpenID\Jws;
use SimpleSAML\OpenID\Jws\Factories\ParsedJwsFactory;
use SimpleSAML\OpenID\Jws\ParsedJws;
use SimpleSAML\OpenID\OAuth2\DpopProof;
use Throwable;

/**
 * @covers \SimpleSAML\Module\oidc\Server\Validators\BearerTokenValidator
 */
#[AllowMockObjectsWithoutExpectations]
class BearerTokenValidatorTest extends TestCase
{
    protected const string RESOURCE_URL = 'https://op.example.org/module.php/oidc/userinfo';

    protected const string JKT = 'thumbprint-of-the-key-the-token-is-bound-to0';


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

    protected MockObject $dpopProofVerifierMock;

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
        $this->moduleConfigMock->method('getDpopSigningAlgorithms')->willReturn(['ES256', 'RS256']);
        $this->dpopProofVerifierMock = $this->createMock(DpopProofVerifier::class);

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
        ?DpopProofVerifier $dpopProofVerifier = null,
    ): BearerTokenValidator {
        $accessTokenRepository ??= $this->accessTokenRepositoryMock;
        $moduleConfig ??= $this->moduleConfigMock;
        $jws ??= $this->jwsMock;
        $jwks ??= $this->jwksMock;
        $loggerService ??= $this->loggerServiceMock;
        $dpopProofVerifier ??= $this->dpopProofVerifierMock;

        return new BearerTokenValidator(
            $accessTokenRepository,
            $moduleConfig,
            $jws,
            $jwks,
            $loggerService,
            $dpopProofVerifier,
        );
    }


    /**
     * A request which carries no access token is refused with the bare challenge and no error code (RFC 6750
     * section 3.1), and nothing is parsed.
     */
    public function testRefusesARequestWithoutAnAccessTokenWithTheBareChallenge(): void
    {
        $this->parsedJwsFactoryMock->expects($this->never())->method('fromToken');

        $this->assertRefusedForWantOfAToken($this->serverRequest);
    }


    /**
     * @return array<string,array{0:string}>
     */
    public static function authorizationHeaderWithoutABearerTokenProvider(): array
    {
        return [
            'another scheme' => ['Basic dXNlcjpwYXNz'],
            'the scheme name run into the token' => ['Bearertoken'],
            'the scheme name alone' => ['Bearer'],
            'the DPoP scheme name run into the token' => ['DPoPtoken'],
            'an empty header' => [''],
            'commas only' => [', ,'],
            'another scheme with auth-params' => ['Digest username="alice", realm="op", nonce="n", response="r"'],
            'a comma in a quoted auth-param' => ['Digest realm="op, too", nonce="n"'],
        ];
    }


    /**
     * An Authorization header which carries no Bearer or DPoP token is no token at all: RFC 6750 section 3.1
     * counts a client which "attempted using an unsupported authentication method" as one which sent no
     * credentials. Such a header used to be read as a token and refused as an invalid one, telling the client its
     * token was bad.
     */
    #[DataProvider('authorizationHeaderWithoutABearerTokenProvider')]
    public function testRefusesAnAuthorizationHeaderWithoutABearerTokenAsNoToken(string $header): void
    {
        $this->parsedJwsFactoryMock->expects($this->never())->method('fromToken');

        $this->assertRefusedForWantOfAToken($this->serverRequest->withAddedHeader('Authorization', $header));
    }


    /**
     * @return array<string,array{0:string}>
     */
    public static function bearerSchemeSpellingProvider(): array
    {
        return [
            'lower case' => ['bearer token'],
            'upper case' => ['BEARER token'],
            'blanks between' => ['Bearer   token'],
            'a tab between' => ["Bearer\ttoken"],
        ];
    }


    /**
     * The scheme name is matched case-insensitively, as HTTP has it (RFC 9110 section 11.1), and the token is
     * whatever follows the blanks after it.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    #[DataProvider('bearerSchemeSpellingProvider')]
    public function testReadsTheTokenWhateverTheCaseOfTheSchemeName(string $header): void
    {
        $this->parsedJwsFactoryMock->expects($this->once())->method('fromToken')
            ->with($this->accessToken)
            ->willReturn($this->parsedJwsMock);

        $validatedServerRequest = $this->sut()->validateAuthorization(
            $this->serverRequest->withAddedHeader('Authorization', $header),
        );

        $this->assertSame(
            $this->accessTokenState['id'],
            $validatedServerRequest->getAttribute('oauth_access_token_id'),
        );
    }


    /**
     * A token which PHP counts as false is still a token which arrived: it is checked, and refused as a token
     * if it fails, never taken for a missing one.
     */
    public function testChecksAHeaderTokenWhichPhpCountsAsFalse(): void
    {
        $this->parsedJwsFactoryMock->expects($this->once())->method('fromToken')
            ->with('0')
            ->willThrowException(new JwsException('Unparsable'));

        $this->assertRefusedAsAnInvalidToken(
            $this->refusalOf($this->serverRequest->withAddedHeader('Authorization', 'Bearer 0')),
        );
    }


    public function testChecksABodyTokenWhichPhpCountsAsFalse(): void
    {
        $this->parsedJwsFactoryMock->expects($this->once())->method('fromToken')
            ->with('0')
            ->willThrowException(new JwsException('Unparsable'));

        $this->assertRefusedAsAnInvalidToken(
            $this->refusalOf($this->serverRequest->withMethod('POST')->withParsedBody(['access_token' => '0'])),
        );
    }


    /**
     * A header under another scheme carries no Bearer token, so the one in the request body is the token the
     * request carries.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testReadsTheBodyTokenWhenTheHeaderNamesAnotherScheme(): void
    {
        $serverRequest = $this->serverRequest
            ->withMethod('POST')
            ->withAddedHeader('Authorization', 'Basic dXNlcjpwYXNz')
            ->withParsedBody(['access_token' => $this->accessToken]);

        $this->parsedJwsFactoryMock->expects($this->once())->method('fromToken')
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


    public function testRefusesAnUnparsableAccessTokenAsAnInvalidToken(): void
    {
        $serverRequest = $this->serverRequest->withAddedHeader('Authorization', 'Bearer ' . 'invalid');

        $unparsable = new JwsException('Unparsable');
        $this->parsedJwsFactoryMock->method('fromToken')
            ->with('invalid')
            ->willThrowException($unparsable);

        $exception = $this->refusalOf($serverRequest);

        $this->assertRefusedAsAnInvalidToken($exception);
        $this->assertSame($unparsable, $exception->getPrevious());
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
     * A token which arrived and fails a check is refused with `invalid_token`, named in the challenge as well
     * (RFC 6750 section 3.1), and with the check's own reason as the hint.
     */
    public function testRefusesARevokedAccessTokenAsAnInvalidToken(): void
    {
        $this->accessTokenRepositoryMock->method('isAccessTokenRevoked')->willReturn(true);

        $this->parsedJwsFactoryMock->method('fromToken')
            ->with($this->accessToken)
            ->willReturn($this->parsedJwsMock);

        $exception = $this->refusalOf($this->bearerRequest());

        $this->assertRefusedAsAnInvalidToken($exception);
        $this->assertSame('Access token has been revoked', $exception->getHint());
        $this->assertInstanceOf(JwsException::class, $exception->getPrevious());
    }


    /**
     * A token of this OP's signing with no record behind it (its client deleted since, say) is a verdict on the
     * token, as the library's are.
     */
    public function testRefusesATokenWithNoRecordAsAnInvalidToken(): void
    {
        $notFound = new TokenNotFoundException('AccessToken not found: accessToken123');
        $this->accessTokenRepositoryMock->method('isAccessTokenRevoked')->willThrowException($notFound);
        $this->parsedJwsFactoryMock->method('fromToken')->willReturn($this->parsedJwsMock);

        $exception = $this->refusalOf($this->bearerRequest());

        $this->assertRefusedAsAnInvalidToken($exception);
        $this->assertSame($notFound, $exception->getPrevious());
    }


    /**
     * @return array<string,array{0:\Throwable}>
     */
    public static function failureWhileCheckingProvider(): array
    {
        return [
            // SimpleSAMLphp's database layer throws a plain Exception, a fetch a PDOException.
            'a database which does not answer' => [new Exception('Database error: connection refused')],
            'a failed fetch' => [new PDOException('SQLSTATE[HY000]: General error')],
            // The parent of the repository's own verdict, which must not pass for one.
            'a runtime failure' => [new RuntimeException('Unexpected failure')],
            // A record which can not be read back into a token, as the entity factory refuses one.
            'a corrupt record' => [OidcServerException::serverError('Invalid Access Token Entity state')],
        ];
    }


    /**
     * A failure of the OP's own while it checks the token is not a verdict on the token: answered as one, it
     * would tell a client holding a working token to throw it away. It is a `server_error`, with the cause kept
     * for the log and out of what the client is shown.
     */
    #[DataProvider('failureWhileCheckingProvider')]
    public function testAnswersAFailureWhileCheckingTheTokenAsTheServersOwn(Throwable $failure): void
    {
        $this->accessTokenRepositoryMock->method('isAccessTokenRevoked')->willThrowException($failure);
        $this->parsedJwsFactoryMock->method('fromToken')->willReturn($this->parsedJwsMock);

        $this->assertAnsweredAsAServerError($this->refusalOf($this->bearerRequest()), $failure);
    }


    public function testAnswersAnUnreadableSigningKeyConfigurationAsTheServersOwn(): void
    {
        $failure = new ConfigurationError('No protocol signing key.');
        $this->moduleConfigMock->method('getProtocolSignatureKeyPairBag')->willThrowException($failure);
        $this->parsedJwsFactoryMock->method('fromToken')->willReturn($this->parsedJwsMock);

        $this->assertAnsweredAsAServerError($this->refusalOf($this->bearerRequest()), $failure);
    }


    /**
     * The claims read after the checks are the token's too: one the library can not read is a verdict on the
     * token, where it used to escape the resource server as the library's own exception.
     */
    public function testRefusesATokenWhoseAudienceCanNotBeReadAsAnInvalidToken(): void
    {
        $accessToken = $this->createMock(ParsedJws::class);
        $accessToken->method('getIssuer')->willReturn('issuer123');
        $accessToken->method('getJwtId')->willReturn('accessToken123');
        $unreadable = new InvalidValueException('Unexpected aud');
        $accessToken->method('getAudience')->willThrowException($unreadable);
        $this->parsedJwsFactoryMock->method('fromToken')->willReturn($accessToken);

        $exception = $this->refusalOf($this->bearerRequest());

        $this->assertRefusedAsAnInvalidToken($exception);
        $this->assertSame($unreadable, $exception->getPrevious());
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
            $this->assertRefusedAsAnInvalidToken($exception);
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
            $this->assertRefusedAsAnInvalidToken($exception);
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
            $this->assertRefusedAsAnInvalidToken($exception);
            $this->assertStringContainsString('Unexpected typ', (string)$exception->getHint());
        }
    }


    /**
     * @return array<string,array{0:?string}>
     */
    public static function unusableJwtIdProvider(): array
    {
        return [
            'no jti claim at all' => [null],
            'a jti which is the empty string' => [''],
        ];
    }


    /**
     * A token without a usable `jti` cannot be looked up in the revocation table, so it is refused before
     * that table is asked. The issuer is stated here because a token double which answers null to
     * everything is refused for the missing issuer first, and this test is about the identifier.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    #[DataProvider('unusableJwtIdProvider')]
    public function testThrowsForEmptyAccessTokenJti(?string $jwtId)
    {
        $accessToken = $this->createMock(ParsedJws::class);
        $accessToken->method('getIssuer')->willReturn('issuer123');
        $accessToken->method('getJwtId')->willReturn($jwtId);
        $this->parsedJwsFactoryMock->method('fromToken')
            ->with($this->accessToken)
            ->willReturn($accessToken);
        $this->accessTokenRepositoryMock->expects($this->never())->method('isAccessTokenRevoked');

        $serverRequest = $this->serverRequest->withAddedHeader('Authorization', 'Bearer ' . $this->accessToken);

        try {
            $this->sut()->validateAuthorization($serverRequest);
            $this->fail('An access token with no jti must be refused.');
        } catch (OidcServerException $exception) {
            $this->assertRefusedAsAnInvalidToken($exception);
            $this->assertStringContainsString('jti missing or unexpected type', (string)$exception->getHint());
        }
    }


    /**
     * The issuer claim is what ties the token to this OP. A token double which answers null to it stands for
     * a token which carries none.
     */
    public function testRefusesAnAccessTokenWhichCarriesNoIssuer(): void
    {
        $accessToken = $this->createMock(ParsedJws::class);
        $this->parsedJwsFactoryMock->method('fromToken')->willReturn($accessToken);

        $this->expectException(JwsException::class);
        $this->expectExceptionMessage('Access token malformed (iss missing or unexpected type)');

        $this->sut()->ensureValidAccessToken($this->accessToken);
    }


    /**
     * A token signed by another authorization server, or by this one under a different issuer identifier, is
     * refused even when its signature verifies: the key set is this OP's, but the issuer names the OP the
     * token was minted for.
     */
    public function testRefusesAnAccessTokenIssuedByAnotherIssuer(): void
    {
        $accessToken = $this->createMock(ParsedJws::class);
        $accessToken->method('getIssuer')->willReturn('https://other-op.example.org');
        $accessToken->method('getJwtId')->willReturn('accessToken123');
        $this->parsedJwsFactoryMock->method('fromToken')->willReturn($accessToken);
        $this->accessTokenRepositoryMock->expects($this->never())->method('isAccessTokenRevoked');

        $this->expectException(JwsException::class);
        $this->expectExceptionMessage('Access token malformed (iss does not match)');

        $this->sut()->ensureValidAccessToken($this->accessToken);
    }


    /**
     * `validateAuthorization()` reads the identifier again after `ensureValidAccessToken()` has already
     * checked it, and refuses the request if it is gone. No parsed token can answer differently on two
     * calls, so the guard is defensive; the double here answers the identifier once and then null, which is
     * the only way to reach it. Removing the second read makes this test fail on the refusal it expects
     * (verified by canary on 2026-09-27: the request then reaches the `aud` conversion, which refuses the
     * double's absent audience instead, with a different hint).
     */
    public function testRefusesATokenWhoseIdentifierIsGoneOnTheSecondRead(): void
    {
        $accessToken = $this->createMock(ParsedJws::class);
        $accessToken->method('getIssuer')->willReturn('issuer123');
        $accessToken->method('getJwtId')->willReturnOnConsecutiveCalls('accessToken123', null);
        $this->parsedJwsFactoryMock->method('fromToken')->willReturn($accessToken);

        $serverRequest = $this->serverRequest->withAddedHeader('Authorization', 'Bearer ' . $this->accessToken);

        try {
            $this->sut()->validateAuthorization($serverRequest);
            $this->fail('A token whose jti is gone must be refused.');
        } catch (OidcServerException $exception) {
            $this->assertRefusedAsAnInvalidToken($exception);
            $this->assertStringContainsString(
                'Access token malformed (jti missing or unexpected type)',
                (string)$exception->getHint(),
            );
        }
    }


    /**
     * The shapes the one production caller can hand over. `ParsedJws::getAudience()` is typed `?array` and
     * wraps a string claim into `[$aud]`, refusing any member which is not a string
     * (`ensureArrayWithValuesAsStrings()`), so from `validateAuthorization()` this method only ever sees
     * null or an array of strings.
     *
     * @return array<string,array{0:mixed,1:array|string}>
     */
    public static function audienceProvider(): array
    {
        return [
            'a single-record array becomes that record' => [['clientId'], 'clientId'],
            'two records stay an array' => [['clientId', 'otherClientId'], ['clientId', 'otherClientId']],
            // The one lax shape a real token can reach: an empty `aud` member names nobody and is still
            // passed on as the client identifier. Section 13 of the todo has it.
            'a single empty record stays empty' => [[''], ''],
        ];
    }


    /**
     * `aud` is a string or an array of strings (RFC 7519 section 4.1.3), and league's request attribute
     * expects one client identifier, so a batch of one is unwrapped for it while a real batch is passed on.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    #[DataProvider('audienceProvider')]
    public function testConvertsTheAudienceClaimForLeague(mixed $aud, array|string $expected): void
    {
        $this->assertSame($expected, $this->sut()->convertSingleRecordAudToString($aud));
    }


    /**
     * The method is public and typed `mixed`, so these shapes are its own contract rather than anything
     * `getAudience()` can produce: a bare string is returned as it stands (that branch is unreachable from
     * `validateAuthorization()`), and a single record which is not a string is cast.
     *
     * @return array<string,array{0:mixed,1:array|string}>
     */
    public static function directCallerAudienceProvider(): array
    {
        return [
            'a bare string is passed through' => ['clientId', 'clientId'],
            'an empty bare string, likewise' => ['', ''],
            'a single record which is not a string is cast' => [[42], '42'],
            'a single null record becomes an empty identifier' => [[null], ''],
            'records which are not strings are passed on as they are' => [[42, 43], [42, 43]],
        ];
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    #[DataProvider('directCallerAudienceProvider')]
    public function testConvertsAnAudienceOnlyADirectCallerCanPass(mixed $aud, array|string $expected): void
    {
        $this->assertSame($expected, $this->sut()->convertSingleRecordAudToString($aud));
    }


    /**
     * @return array<string,array{0:mixed}>
     */
    public static function unusableAudienceProvider(): array
    {
        return [
            // Both of these a real token reaches: an `aud` array which is empty, and no `aud` at all.
            'an empty array' => [[]],
            'null' => [null],
            // These are the method's own contract, as above.
            'an integer' => [42],
            'a boolean' => [true],
            'a float' => [1.5],
        ];
    }


    /**
     * An `aud` which is neither a string nor a non-empty array cannot be resolved to the client the token
     * was issued to, so the request is refused rather than carried on. An empty string is not refused: it
     * is a string, and `is_string()` is asked first (`directCallerAudienceProvider`, section 13).
     */
    #[DataProvider('unusableAudienceProvider')]
    public function testRefusesAnAudienceClaimWhichNamesNobody(mixed $aud): void
    {
        try {
            $this->sut()->convertSingleRecordAudToString($aud);
            $this->fail('An aud of ' . var_export($aud, true) . ' must be refused.');
        } catch (OidcServerException $exception) {
            $this->assertRefusedAsAnInvalidToken($exception);
            $this->assertSame('Unexpected aud claim value.', $exception->getHint());
        }
    }


    /**
     * @return array<string,array{0:string}>
     */
    public static function dpopSchemeWithoutATokenProvider(): array
    {
        return [
            'the scheme name alone' => ['DPoP'],
            'blanks after it' => ['dpop  '],
        ];
    }


    /**
     * A request which names the DPoP scheme with nothing after it carried no credentials either: the challenge is
     * the DPoP one, the scheme it tried, with no error information (RFC 9449 section 7.2, Figure 17), and no body.
     */
    #[DataProvider('dpopSchemeWithoutATokenProvider')]
    public function testRefusesTheDpopSchemeWithoutATokenWithTheBareDpopChallenge(string $header): void
    {
        $this->parsedJwsFactoryMock->expects($this->never())->method('fromToken');

        $exception = $this->refusalOf($this->resourceRequest()->withAddedHeader('Authorization', $header));

        $this->assertSame(401, $exception->getHttpStatusCode());
        $this->assertSame('DPoP algs="ES256 RS256"', $exception->getWwwAuthenticate());
        $this->assertFalse($exception->hasBody());
    }


    /**
     * Without the header in what PHP is given, the one Apache kept is read: every entry named Authorization in any
     * case, so that two of them are two values. A warning says the configuration is to be fixed.
     */
    public function testReadsTheAuthorizationHeaderApacheKept(): void
    {
        $this->parsedJwsFactoryMock->expects($this->once())->method('fromToken')
            ->with($this->accessToken)
            ->willReturn($this->parsedJwsMock);
        // Once for each of the two requests below.
        $this->loggerServiceMock->expects($this->exactly(2))->method('warning')
            ->with($this->stringContains('Apache stripping of Authorization'));

        $validated = $this->sutWithApacheHeaders(['AUTHORIZATION' => 'Bearer ' . $this->accessToken])
            ->validateAuthorization($this->serverRequest);

        $this->assertSame($this->accessTokenState['id'], $validated->getAttribute('oauth_access_token_id'));

        $exception = $this->refusalOf(
            $this->serverRequest,
            $this->sutWithApacheHeaders(['Authorization' => 'DPoP token', 'authorization' => 'Bearer token']),
        );

        $this->assertSame('invalid_request', $exception->getErrorType());
        $this->assertSame(
            'Bearer error="invalid_request", DPoP error="invalid_request", algs="ES256 RS256"',
            $exception->getWwwAuthenticate(),
        );
    }


    /**
     * Apache's view is read only for a request PHP was given no Authorization header with.
     */
    public function testReadsApachesHeaderOnlyWhenPhpHasNone(): void
    {
        $this->parsedJwsFactoryMock->expects($this->once())->method('fromToken')
            ->with($this->accessToken)
            ->willReturn($this->parsedJwsMock);

        $this->sutWithApacheHeaders(['Authorization' => 'Bearer another-token'])
            ->validateAuthorization($this->bearerRequest());
    }


    /**
     * RFC 9449 section 7.2: a `cnf` claim carried with a null value is still one, and the token is refused under
     * the Bearer scheme and in the body; under the DPoP scheme it is no binding to a key.
     */
    public function testRefusesATokenWithAnExplicitlyNullConfirmation(): void
    {
        $this->bindParsedTokenTo(null, true);
        $this->parsedJwsFactoryMock->method('fromToken')->willReturn($this->parsedJwsMock);
        $this->dpopProofVerifierMock->expects($this->never())->method('verify');

        foreach (
            [
                $this->bearerRequest(),
                $this->serverRequest->withMethod('POST')->withParsedBody(['access_token' => $this->accessToken]),
            ] as $request
        ) {
            $exception = $this->refusalOf($request);
            $this->assertRefusedAsAnInvalidToken($exception);
            $this->assertStringContainsString('only under the DPoP scheme', (string)$exception->getHint());
        }

        $this->assertRefusedUnderTheDpopScheme($this->refusalOf($this->dpopRequest()), 'invalid_token', 401);
    }


    /**
     * The scheme the token was presented under is passed on: Bearer for the header under that scheme and for the
     * body, and no DPoP proof is looked for.
     */
    public function testPassesTheBearerSchemeOnForATokenInTheHeaderOrTheBody(): void
    {
        $this->parsedJwsFactoryMock->method('fromToken')->willReturn($this->parsedJwsMock);
        $this->dpopProofVerifierMock->expects($this->never())->method('verify');

        foreach (
            [
                $this->bearerRequest(),
                $this->serverRequest->withMethod('POST')->withParsedBody(['access_token' => $this->accessToken]),
            ] as $request
        ) {
            $this->assertSame(
                'Bearer',
                $this->sut()->validateAuthorization($request->withHeader('DPoP', 'a-proof'))
                    ->getAttribute(BearerTokenValidator::ATTRIBUTE_ACCESS_TOKEN_SCHEME),
            );
        }
    }


    /**
     * @return array<string,array{0:string}>
     */
    public static function dpopSchemeSpellingProvider(): array
    {
        return [
            'as RFC 9449 writes it' => ['DPoP token'],
            'lower case' => ['dpop token'],
            'upper case' => ['DPOP token'],
            'a tab between' => ["DPoP\ttoken"],
        ];
    }


    /**
     * A token under the DPoP scheme (RFC 9449 section 7.1) is read too, the scheme name matched case-insensitively,
     * and accepted when it is bound to the key of the proof which came with it: the proof is checked against the
     * URL the resource named and the token exactly as it came. The scheme is passed on.
     */
    #[DataProvider('dpopSchemeSpellingProvider')]
    public function testAcceptsATokenUnderTheDpopSchemeWithAProofByTheKeyItIsBoundTo(string $header): void
    {
        $this->bindParsedTokenTo([ClaimsEnum::Jkt->value => self::JKT]);
        $this->parsedJwsFactoryMock->expects($this->once())->method('fromToken')
            ->with($this->accessToken)
            ->willReturn($this->parsedJwsMock);
        $request = $this->resourceRequest()->withAddedHeader('Authorization', $header);
        $this->dpopProofVerifierMock->expects($this->once())->method('verify')
            ->with($request, self::RESOURCE_URL, $this->accessToken)
            ->willReturn($this->verifiedProofBy(self::JKT));

        $validated = $this->sut()->validateAuthorization($request);

        $this->assertSame('accessToken123', $validated->getAttribute('oauth_access_token_id'));
        $this->assertSame('DPoP', $validated->getAttribute(BearerTokenValidator::ATTRIBUTE_ACCESS_TOKEN_SCHEME));
    }


    /**
     * @return array<string,array{0:string[],1:?string,2:bool}>
     */
    public static function moreThanOneMethodProvider(): array
    {
        return [
            'the header and the body' => [['Bearer token'], 'token', false],
            'two Authorization fields' => [['Bearer token', 'Bearer other'], null, false],
            'two values joined into one field' => [['Bearer token, Bearer other'], null, false],
            'a Basic and a Bearer value' => [['Basic dXNlcjpwYXNz, Bearer token'], null, false],
            'a Bearer and a DPoP value' => [['Bearer token, DPoP token'], null, true],
            'two Authorization fields, one of them DPoP' => [['Bearer token', 'DPoP token'], null, true],
            'the DPoP scheme and the body' => [['DPoP token'], 'token', true],
            'auth-params of another scheme, then a Bearer value' => [
                ['Digest username="alice", realm="op, too", Bearer token'],
                null,
                false,
            ],
        ];
    }


    /**
     * RFC 6750 section 2: "Clients MUST NOT use more than one method to transmit the token in each request". Such
     * a request is refused as `invalid_request` with a 400 (section 3.1), and no token is checked, since which one
     * the client meant can not be known. Where one of the methods is the DPoP scheme, a DPoP challenge names the
     * error too (RFC 9449 section 7.2, Figure 19). The header used to win silently.
     *
     * @param string[] $authorization
     */
    #[DataProvider('moreThanOneMethodProvider')]
    public function testRefusesARequestWhichPresentsATokenMoreThanOneWay(
        array $authorization,
        ?string $bodyToken,
        bool $isDpopAmongThem,
    ): void {
        $this->parsedJwsFactoryMock->expects($this->never())->method('fromToken');
        $this->dpopProofVerifierMock->expects($this->never())->method('verify');
        $request = $this->resourceRequest()->withMethod('POST');
        foreach ($authorization as $value) {
            $request = $request->withAddedHeader('Authorization', $value);
        }
        if ($bodyToken !== null) {
            $request = $request->withParsedBody(['access_token' => $bodyToken]);
        }

        $exception = $this->refusalOf($request);

        $this->assertSame('invalid_request', $exception->getErrorType());
        $this->assertSame(400, $exception->getHttpStatusCode());
        $this->assertSame(
            'Bearer error="invalid_request"' .
            ($isDpopAmongThem ? ', DPoP error="invalid_request", algs="ES256 RS256"' : ''),
            $exception->getWwwAuthenticate(),
        );
    }


    /**
     * A header under another scheme whose auth-params are separated by commas (RFC 9110 section 11.4) is one
     * value, not several, so the token in the body is the one the request carries.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testReadsTheBodyTokenNextToAnotherSchemesAuthParams(): void
    {
        $this->parsedJwsFactoryMock->expects($this->once())->method('fromToken')
            ->with($this->accessToken)
            ->willReturn($this->parsedJwsMock);
        $request = $this->serverRequest
            ->withMethod('POST')
            // A comma inside a quoted-string, after an escaped quote which does not end it.
            ->withAddedHeader('Authorization', 'Digest username="alice", realm="a \\", b", nonce="n"')
            ->withParsedBody(['access_token' => $this->accessToken]);

        $this->assertSame(
            $this->accessTokenState['id'],
            $this->sut()->validateAuthorization($request)->getAttribute('oauth_access_token_id'),
        );
    }


    /**
     * @return array<string,array{0:string[]}>
     */
    public static function authorizationWithAnEmptyListElementProvider(): array
    {
        return [
            'a trailing comma' => [['Bearer token,']],
            'a leading comma' => [[', Bearer token']],
            'an empty field beside it' => [['', 'Bearer token']],
        ];
    }


    /**
     * An empty element of the Authorization list is no value (RFC 9110 section 5.6.1), so the one beside it is
     * the only one.
     *
     * @param string[] $authorization
     */
    #[DataProvider('authorizationWithAnEmptyListElementProvider')]
    public function testSkipsAnEmptyElementOfTheAuthorizationList(array $authorization): void
    {
        $this->parsedJwsFactoryMock->expects($this->once())->method('fromToken')
            ->with($this->accessToken)
            ->willReturn($this->parsedJwsMock);
        $request = $this->serverRequest;
        foreach ($authorization as $value) {
            $request = $request->withAddedHeader('Authorization', $value);
        }

        $this->assertSame(
            $this->accessTokenState['id'],
            $this->sut()->validateAuthorization($request)->getAttribute('oauth_access_token_id'),
        );
    }


    /**
     * @return array<string,array{0:string,1:mixed}>
     */
    public static function boundTokenOutsideTheDpopSchemeProvider(): array
    {
        return [
            'under the Bearer scheme' => ['header', [ClaimsEnum::Jkt->value => self::JKT]],
            'in the body' => ['body', [ClaimsEnum::Jkt->value => self::JKT]],
            'confirmed by another method' => ['header', ['x5t#S256' => 'thumbprint-of-a-certificate']],
            'a confirmation which is no object' => ['header', 'bound'],
        ];
    }


    /**
     * RFC 9449 section 7.2: a resource which accepts both schemes "MUST reject a DPoP-bound access token received
     * as a bearer token", whether in the header or in the body, and a proof sent along does not make up for the
     * scheme. Any `cnf` claim counts, since the module writes none but the binding.
     */
    #[DataProvider('boundTokenOutsideTheDpopSchemeProvider')]
    public function testRefusesABoundTokenPresentedAsABearerToken(string $where, mixed $confirmation): void
    {
        $this->bindParsedTokenTo($confirmation);
        $this->parsedJwsFactoryMock->method('fromToken')->willReturn($this->parsedJwsMock);
        $this->dpopProofVerifierMock->expects($this->never())->method('verify');
        $request = $where === 'header' ?
        $this->bearerRequest() :
        $this->serverRequest->withMethod('POST')->withParsedBody(['access_token' => $this->accessToken]);

        $exception = $this->refusalOf($request->withHeader('DPoP', 'a-proof'));

        $this->assertRefusedAsAnInvalidToken($exception);
        $this->assertStringContainsString('only under the DPoP scheme', (string)$exception->getHint());
    }


    /**
     * @return array<string,array{0:mixed}>
     */
    public static function tokenNotBoundByThumbprintProvider(): array
    {
        return [
            'no cnf' => [null],
            'an empty cnf' => [[]],
            'confirmed by another method' => [['x5t#S256' => 'thumbprint-of-a-certificate']],
            'a jkt which is no string' => [[ClaimsEnum::Jkt->value => 42]],
            'an empty jkt' => [[ClaimsEnum::Jkt->value => '']],
            'a confirmation which is no object' => [self::JKT],
        ];
    }


    /**
     * Under the DPoP scheme only a token bound to a key by `cnf.jkt` is accepted (RFC 9449 section 6.1); any other
     * is refused as `invalid_token`, in a DPoP challenge, before any proof is looked at. Until the token endpoint
     * binds tokens, that is every token.
     */
    #[DataProvider('tokenNotBoundByThumbprintProvider')]
    public function testRefusesATokenNotBoundByThumbprintUnderTheDpopScheme(mixed $confirmation): void
    {
        $this->bindParsedTokenTo($confirmation);
        $this->parsedJwsFactoryMock->method('fromToken')->willReturn($this->parsedJwsMock);
        $this->dpopProofVerifierMock->expects($this->never())->method('verify');

        $exception = $this->refusalOf($this->dpopRequest());

        $this->assertRefusedUnderTheDpopScheme($exception, 'invalid_token', 401);
        $this->assertStringContainsString('not a DPoP-bound access token', (string)$exception->getHint());
    }


    /**
     * RFC 9449 section 7.1 has the resource "ensure that a DPoP proof was received": a bound token without one is
     * `invalid_dpop_proof`.
     */
    public function testRefusesABoundTokenUnderTheDpopSchemeWithoutAProof(): void
    {
        $this->bindParsedTokenTo([ClaimsEnum::Jkt->value => self::JKT]);
        $this->parsedJwsFactoryMock->method('fromToken')->willReturn($this->parsedJwsMock);
        $this->dpopProofVerifierMock->method('verify')->willReturn(null);

        $exception = $this->refusalOf($this->dpopRequest());

        $this->assertRefusedUnderTheDpopScheme($exception, 'invalid_dpop_proof', 401);
        $this->assertStringContainsString('A DPoP proof is required', (string)$exception->getHint());
    }


    /**
     * The verifier's refusal of the proof, or its own failure, is the answer as it stands.
     */
    public function testLetsTheVerifiersRefusalThrough(): void
    {
        $this->bindParsedTokenTo([ClaimsEnum::Jkt->value => self::JKT]);
        $this->parsedJwsFactoryMock->method('fromToken')->willReturn($this->parsedJwsMock);
        $refusal = OidcServerException::invalidDpopProof('The DPoP proof has been used before.', 'DPoP');
        $this->dpopProofVerifierMock->method('verify')->willThrowException($refusal);

        $this->assertSame($refusal, $this->refusalOf($this->dpopRequest()));
    }


    /**
     * RFC 9449 section 7.1, Figure 16: a proof by another key than the one the token is bound to is
     * `invalid_token`.
     */
    public function testRefusesAProofByAnotherKeyAsAnInvalidToken(): void
    {
        $this->bindParsedTokenTo([ClaimsEnum::Jkt->value => self::JKT]);
        $this->parsedJwsFactoryMock->method('fromToken')->willReturn($this->parsedJwsMock);
        $this->dpopProofVerifierMock->method('verify')->willReturn($this->verifiedProofBy(strrev(self::JKT)));

        $exception = $this->refusalOf($this->dpopRequest());

        $this->assertRefusedUnderTheDpopScheme($exception, 'invalid_token', 401);
        $this->assertStringContainsString('not signed by the key', (string)$exception->getHint());
    }


    /**
     * Without the URL of the resource no proof can be checked, which is the caller's fault, not the request's.
     */
    public function testAnswersAResourceWhichDidNotNameItsUrlAsTheServersOwnFailure(): void
    {
        $this->bindParsedTokenTo([ClaimsEnum::Jkt->value => self::JKT]);
        $this->parsedJwsFactoryMock->method('fromToken')->willReturn($this->parsedJwsMock);
        $this->dpopProofVerifierMock->expects($this->never())->method('verify');

        $exception = $this->refusalOf(
            $this->serverRequest->withAddedHeader('Authorization', 'DPoP ' . $this->accessToken),
        );

        $this->assertSame('server_error', $exception->getErrorType());
        $this->assertSame(500, $exception->getHttpStatusCode());
    }


    /**
     * A token presented under the DPoP scheme which fails a check of its own is refused in a DPoP challenge: the
     * Bearer one would tell the client to try the other scheme.
     */
    public function testRefusesAnInvalidTokenUnderTheDpopSchemeInADpopChallenge(): void
    {
        $this->parsedJwsFactoryMock->method('fromToken')->willThrowException(new JwsException('Unparsable'));
        $this->dpopProofVerifierMock->expects($this->never())->method('verify');

        $this->assertRefusedUnderTheDpopScheme($this->refusalOf($this->dpopRequest()), 'invalid_token', 401);
    }


    public function testRefusesATokenWhoseIdentifierIsGoneUnderTheDpopSchemeInADpopChallenge(): void
    {
        $accessToken = $this->createMock(ParsedJws::class);
        $accessToken->method('getIssuer')->willReturn('issuer123');
        $accessToken->method('getJwtId')->willReturnOnConsecutiveCalls('accessToken123', null);
        $this->parsedJwsFactoryMock->method('fromToken')->willReturn($accessToken);

        $this->assertRefusedUnderTheDpopScheme($this->refusalOf($this->dpopRequest()), 'invalid_token', 401);
    }


    public function testRefusesAnUnusableAudienceUnderTheDpopSchemeInADpopChallenge(): void
    {
        $accessToken = $this->createMock(ParsedJws::class);
        $accessToken->method('getIssuer')->willReturn('issuer123');
        $accessToken->method('getJwtId')->willReturn('accessToken123');
        $this->parsedJwsFactoryMock->method('fromToken')->willReturn($accessToken);

        $this->assertRefusedUnderTheDpopScheme($this->refusalOf($this->dpopRequest()), 'invalid_token', 401);
    }


    protected function bearerRequest(): ServerRequestInterface
    {
        return $this->serverRequest->withAddedHeader('Authorization', 'Bearer ' . $this->accessToken);
    }


    /**
     * A request to the resource, which names its URL as ResourceServer does.
     */
    protected function resourceRequest(): ServerRequestInterface
    {
        return $this->serverRequest->withAttribute(BearerTokenValidator::ATTRIBUTE_RESOURCE_URL, self::RESOURCE_URL);
    }


    protected function dpopRequest(): ServerRequestInterface
    {
        return $this->resourceRequest()->withAddedHeader('Authorization', 'DPoP ' . $this->accessToken);
    }


    /**
     * The parsed token answers with the confirmation given for its `cnf` claim, and with null for every other; the
     * claim counts as present unless it is null, or as $isPresent says.
     */
    protected function bindParsedTokenTo(mixed $confirmation, ?bool $isPresent = null): void
    {
        $isPresent ??= $confirmation !== null;
        $this->parsedJwsMock->method('getPayloadClaim')->willReturnCallback(
            fn(string $claim): mixed => $claim === ClaimsEnum::Cnf->value ? $confirmation : null,
        );
        $this->parsedJwsMock->method('hasPayloadClaim')->willReturnCallback(
            fn(string $claim): bool => $claim === ClaimsEnum::Cnf->value && $isPresent,
        );
    }


    /**
     * The validator as it runs under an Apache which has the headers given.
     *
     * @param array<string,string> $apacheRequestHeaders
     */
    protected function sutWithApacheHeaders(array $apacheRequestHeaders): BearerTokenValidator
    {
        return new class (
            $this->accessTokenRepositoryMock,
            $this->moduleConfigMock,
            $this->jwsMock,
            $this->jwksMock,
            $this->loggerServiceMock,
            $this->dpopProofVerifierMock,
            $apacheRequestHeaders,
        ) extends BearerTokenValidator {
            /** @param array<string,string> $apacheRequestHeaders */
            public function __construct(
                AccessTokenRepository $accessTokenRepository,
                ModuleConfig $moduleConfig,
                Jws $jws,
                Jwks $jwks,
                LoggerService $loggerService,
                DpopProofVerifier $dpopProofVerifier,
                private readonly array $apacheRequestHeaders,
            ) {
                parent::__construct(
                    $accessTokenRepository,
                    $moduleConfig,
                    $jws,
                    $jwks,
                    $loggerService,
                    $dpopProofVerifier,
                );
            }


            protected function getApacheRequestHeaders(): array
            {
                return $this->apacheRequestHeaders;
            }
        };
    }


    protected function verifiedProofBy(string $jwkThumbprint): VerifiedDpopProof
    {
        return new VerifiedDpopProof($this->createStub(DpopProof::class), $jwkThumbprint);
    }


    protected function assertRefusedUnderTheDpopScheme(
        OidcServerException $exception,
        string $error,
        int $status,
    ): void {
        $this->assertSame($error, $exception->getErrorType());
        $this->assertSame($status, $exception->getHttpStatusCode());
        $this->assertSame(sprintf('DPoP error="%s", algs="ES256 RS256"', $error), $exception->getWwwAuthenticate());
        $this->assertTrue($exception->hasBody());
    }


    protected function refusalOf(
        ServerRequestInterface $serverRequest,
        ?BearerTokenValidator $sut = null,
    ): OidcServerException {
        try {
            ($sut ?? $this->sut())->validateAuthorization($serverRequest);
        } catch (OidcServerException $exception) {
            return $exception;
        }

        $this->fail('The request must be refused.');
    }


    protected function assertRefusedAsAnInvalidToken(OidcServerException $exception): void
    {
        $this->assertSame('invalid_token', $exception->getErrorType());
        $this->assertSame(401, $exception->getHttpStatusCode());
        $this->assertSame('Bearer error="invalid_token"', $exception->getWwwAuthenticate());
        $this->assertTrue($exception->hasBody());
    }


    protected function assertRefusedForWantOfAToken(ServerRequestInterface $serverRequest): void
    {
        $exception = $this->refusalOf($serverRequest);

        $this->assertSame(401, $exception->getHttpStatusCode());
        $this->assertSame('Bearer', $exception->getWwwAuthenticate());
        $this->assertFalse($exception->hasBody());
        $this->assertSame([], $exception->getPayload());
    }


    protected function assertAnsweredAsAServerError(OidcServerException $exception, Throwable $failure): void
    {
        $this->assertSame('server_error', $exception->getErrorType());
        $this->assertSame(500, $exception->getHttpStatusCode());
        $this->assertNull($exception->getWwwAuthenticate());
        $this->assertSame($failure, $exception->getPrevious());

        // What the client is shown: the payload League renders, and the message and hint the JSON responder does.
        $shown = implode(' ', [...$exception->getPayload(), $exception->getMessage(), (string)$exception->getHint()]);
        $this->assertStringNotContainsString($failure->getMessage(), $shown);
    }
}
