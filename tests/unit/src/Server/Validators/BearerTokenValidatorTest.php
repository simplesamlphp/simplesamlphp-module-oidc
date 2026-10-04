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
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Exceptions\InvalidValueException;
use SimpleSAML\OpenID\Exceptions\JwsException;
use SimpleSAML\OpenID\Helpers;
use SimpleSAML\OpenID\Jwks;
use SimpleSAML\OpenID\Jws;
use SimpleSAML\OpenID\Jws\Factories\ParsedJwsFactory;
use SimpleSAML\OpenID\Jws\ParsedJws;
use Throwable;

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
            'a DPoP token' => ['DPoP token'],
            'the scheme name run into the token' => ['Bearertoken'],
            'the scheme name alone' => ['Bearer'],
            'an empty header' => [''],
        ];
    }


    /**
     * An Authorization header which carries no Bearer token is no token at all: RFC 6750 section 3.1 counts a
     * client which "attempted using an unsupported authentication method" as one which sent no credentials. Such
     * a header used to be read as a token and refused as an invalid one, telling the client its token was bad.
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


    protected function bearerRequest(): ServerRequestInterface
    {
        return $this->serverRequest->withAddedHeader('Authorization', 'Bearer ' . $this->accessToken);
    }


    protected function refusalOf(ServerRequestInterface $serverRequest): OidcServerException
    {
        try {
            $this->sut()->validateAuthorization($serverRequest);
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
