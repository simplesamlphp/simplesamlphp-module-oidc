<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\Grants;

use DateInterval;
use DateTimeImmutable;
use Defuse\Crypto\Crypto;
use Defuse\Crypto\Key;
use JsonException;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface as OAuth2AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\EventEmitting\EventEmitter;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface as OAuth2AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\RequestEvent;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use ReflectionMethod;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\AccessTokenEntityInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\RefreshTokenEntityInterface;
use SimpleSAML\Module\oidc\Factories\Entities\AccessTokenEntityFactory;
use SimpleSAML\Module\oidc\Repositories\Interfaces\AccessTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\Grants\RefreshTokenGrant;
use SimpleSAML\Module\oidc\Server\TokenIssuers\RefreshTokenIssuer;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\AuthenticatedOAuth2ClientResolver;
use SimpleSAML\Module\oidc\ValueAbstracts\ResolvedClientAuthenticationMethod;
use SimpleSAML\OpenID\Codebooks\ClientAuthenticationMethodsEnum;
use Stringable;

/**
 * The grant overrides four of the methods it inherits. `validateOldRefreshToken()` comes from league's own
 * `RefreshTokenGrant`; `validateClient()` and `issueRefreshToken()` are declared on `AbstractGrant`; and
 * `issueAccessToken()` is replaced wholesale by `IssueAccessTokenTrait`. None of the four calls `parent::`
 * -- each replaces the league body rather than extending it. The constructor does call
 * `parent::__construct()`, which is what leaves `refreshTokenTTL` initialised to one month.
 *
 * The tests below are written against those departures, since a regression which restored the league
 * behaviour would still leave a working refresh flow, only a differently behaved one.
 *
 * `validateOldRefreshToken()` differs in six ways. A missing `refresh_token` raises `invalid_grant` where
 * league raises `invalid_request`. The payload is decoded with `JSON_THROW_ON_ERROR` where league decodes
 * silently. A payload which decodes to something other than an array is rejected, which league does not
 * check. The refresh token id is cast to string before the revocation lookup, which league passes through
 * as it found it. And every rejection this method raises itself is logged -- at `notice` where the caller is
 * simply wrong, at `warning` where the request looks like an attack. The one rejection which is not logged
 * is the `JsonException`, which is not caught. And on the way out it can delay a second, which league does
 * not do at all.
 *
 * `validateClient()` resolves the client through `AuthenticatedOAuth2ClientResolver` instead of demanding a
 * `client_id` parameter, and `issueRefreshToken()` delegates to `RefreshTokenIssuer` instead of building the
 * entity itself. All four are protected, so they are reached by reflection.
 *
 * The payload fixture is keyed on the field names written by
 * `League\OAuth2\Server\ResponseTypes\BearerTokenResponse`, which is what produces this payload in the
 * module -- `TokenResponse` extends it without overriding that method -- rather than on the names read back
 * by the code under test.
 *
 * Fixtures are encrypted with a `Defuse\Crypto\Key`. `ModuleConfig::getEncryptionKey()` returns either a
 * `Key` or, when no key is configured, the SimpleSAMLphp secret salt as a password; both are real
 * deployments and `CryptTrait` handles them in branches of its own. The `Key` is used here because a
 * password derives its key on every call: a measured round trip costs around 400ms, and this file does
 * some thirty of them, which would dominate its runtime.
 *
 * `IssueAccessTokenTrait` is exercised here as well. Its lines merge into this class's coverage target
 * because the class uses it, and its repository guard and collision retry are reached from no other test.
 */
#[CoversClass(RefreshTokenGrant::class)]
#[AllowMockObjectsWithoutExpectations]
class RefreshTokenGrantTest extends TestCase
{
    protected const string ACCESS_TOKEN_ID = 'access-token-id';

    protected const string CLIENT_ID = 'test-client-id';

    protected const string OTHER_CLIENT_ID = 'other-client-id';

    protected const string REFRESH_TOKEN_ID = 'refresh-token-id';

    protected const string USER_ID = 'test-user-id';


    protected static ?Key $encryptionKey = null;

    protected MockObject $refreshTokenRepositoryMock;

    protected MockObject $accessTokenEntityFactoryMock;

    protected MockObject $refreshTokenIssuerMock;

    protected MockObject $clientResolverMock;

    protected MockObject $serverRequestMock;

    protected MockObject $loggerServiceMock;

    protected EventEmitter $emitter;

    /** @var string[] */
    protected array $emittedEventNames;

    /** @var array<int, array{0: string|\Stringable, 1: array}> */
    protected array $logCalls;

    /** @var array<int, array> */
    protected array $accessTokenFactoryArguments;


    protected function setUp(): void
    {
        $this->refreshTokenRepositoryMock = $this->createMock(RefreshTokenRepositoryInterface::class);
        $this->accessTokenEntityFactoryMock = $this->createMock(AccessTokenEntityFactory::class);
        $this->refreshTokenIssuerMock = $this->createMock(RefreshTokenIssuer::class);
        $this->clientResolverMock = $this->createMock(AuthenticatedOAuth2ClientResolver::class);
        $this->serverRequestMock = $this->createMock(ServerRequestInterface::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);

        $this->emittedEventNames = [];
        $this->emitter = new EventEmitter();
        // Subscribed by class name rather than by event name: the registry hands an event to a listener
        // whose key the event is an instance of, so this one listener sees every RequestEvent. The tests can
        // then assert the whole list of what was emitted rather than only what they went looking for.
        $this->emitter->addListener(
            RequestEvent::class,
            function (RequestEvent $event): void {
                $this->emittedEventNames[] = $event->eventName();
            },
        );

        $this->logCalls = [];
        $this->accessTokenFactoryArguments = [];
    }


    /**
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     */
    protected static function encryptionKey(): Key
    {
        return self::$encryptionKey ??= Key::createNewRandomKey();
    }


    /**
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     */
    protected function sut(
        ?DateInterval $refreshTokenTtl = null,
        bool $withEncryptionKey = true,
    ): RefreshTokenGrant {
        $grant = new RefreshTokenGrant(
            $this->refreshTokenRepositoryMock,
            $this->accessTokenEntityFactoryMock,
            $this->refreshTokenIssuerMock,
            $this->clientResolverMock,
            $this->loggerServiceMock,
        );

        // A grant carries no key until an AuthorizationServer registers it -- enableGrantType() is what
        // calls setEncryptionKey() -- and an unset key reaches the branch of CryptTrait which refuses to
        // decrypt at all. Passing an explicit null would reach it too.
        if ($withEncryptionKey) {
            $grant->setEncryptionKey(self::encryptionKey());
        }

        $grant->setEmitter($this->emitter);

        if ($refreshTokenTtl !== null) {
            $grant->setRefreshTokenTTL($refreshTokenTtl);
        }

        return $grant;
    }


    /**
     * The fields a refresh token payload carries, in the order BearerTokenResponse writes them.
     *
     * @param array<string, mixed> $overrides
     * @return array<string, mixed>
     */
    protected static function refreshTokenPayload(array $overrides = []): array
    {
        return array_merge(
            [
                'client_id' => self::CLIENT_ID,
                'refresh_token_id' => self::REFRESH_TOKEN_ID,
                'access_token_id' => self::ACCESS_TOKEN_ID,
                'scopes' => ['openid', 'profile'],
                'user_id' => self::USER_ID,
                'expire_time' => time() + 3600,
            ],
            $overrides,
        );
    }


    /**
     * @param array<string, mixed> $payload
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     * @throws \JsonException
     */
    protected static function encryptedPayload(array $payload): string
    {
        return self::encryptedString(json_encode($payload, JSON_THROW_ON_ERROR));
    }


    /**
     * Encryption is done with defuse directly rather than through the grant's own `encrypt()`, so that the
     * fixture is not produced by the object under test.
     *
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     */
    protected static function encryptedString(string $plaintext): string
    {
        return Crypto::encrypt($plaintext, self::encryptionKey());
    }


    /**
     * @param array<string, mixed> $parsedBody
     */
    protected function requestWith(array $parsedBody): ServerRequestInterface
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getParsedBody')->willReturn($parsedBody);

        return $request;
    }


    /**
     * @throws \ReflectionException
     */
    protected function callValidateClient(RefreshTokenGrant $grant): ClientEntity
    {
        $method = new ReflectionMethod(RefreshTokenGrant::class, 'validateClient');

        /** @var \SimpleSAML\Module\oidc\Entities\ClientEntity $client */
        $client = $method->invoke($grant, $this->serverRequestMock);

        return $client;
    }


    /**
     * @param array<string, mixed> $parsedBody
     * @return array<string, mixed>
     * @throws \ReflectionException
     */
    protected function callValidateOldRefreshToken(
        RefreshTokenGrant $grant,
        array $parsedBody,
        string $clientId = self::CLIENT_ID,
    ): array {
        $method = new ReflectionMethod(RefreshTokenGrant::class, 'validateOldRefreshToken');

        /** @var array<string, mixed> $payload */
        $payload = $method->invoke($grant, $this->requestWith($parsedBody), $clientId);

        return $payload;
    }


    /**
     * @param array<string, mixed> $parsedBody
     * @throws \ReflectionException
     */
    protected function rejectionOf(
        RefreshTokenGrant $grant,
        array $parsedBody,
        string $clientId = self::CLIENT_ID,
    ): OidcServerException {
        try {
            $this->callValidateOldRefreshToken($grant, $parsedBody, $clientId);
        } catch (OidcServerException $exception) {
            return $exception;
        }

        $this->fail('The refresh token was accepted where it should have been rejected.');
    }


    /**
     * @throws \ReflectionException
     */
    protected function callIssueRefreshToken(
        RefreshTokenGrant $grant,
        OAuth2AccessTokenEntityInterface $accessToken,
        ?string $authCodeId = null,
    ): ?RefreshTokenEntityInterface {
        $method = new ReflectionMethod(RefreshTokenGrant::class, 'issueRefreshToken');

        /** @var \SimpleSAML\Module\oidc\Entities\Interfaces\RefreshTokenEntityInterface|null $refreshToken */
        $refreshToken = $method->invoke($grant, $accessToken, $authCodeId);

        return $refreshToken;
    }


    /**
     * @param \League\OAuth2\Server\Entities\ScopeEntityInterface[] $scopes
     * @throws \ReflectionException
     */
    protected function callIssueAccessToken(
        RefreshTokenGrant $grant,
        DateInterval $accessTokenTtl,
        ClientEntity $client,
        array $scopes = [],
    ): AccessTokenEntityInterface {
        $method = new ReflectionMethod(RefreshTokenGrant::class, 'issueAccessToken');

        /** @var \SimpleSAML\Module\oidc\Entities\Interfaces\AccessTokenEntityInterface $accessToken */
        $accessToken = $method->invoke($grant, $accessTokenTtl, $client, self::USER_ID, $scopes);

        return $accessToken;
    }


    /**
     * Record what the grant writes at any of the levels it chooses between, so a test can assert on the
     * whole of it without having to predict which one a given path picks.
     */
    protected function captureLogCalls(): void
    {
        foreach (['notice', 'warning', 'error'] as $level) {
            $this->loggerServiceMock->method($level)->willReturnCallback(
                function (string|Stringable $message, array $context = []): void {
                    $this->logCalls[] = [$message, $context];
                },
            );
        }
    }


    /**
     * The refresh grant must authenticate the client via the resolver (which supports private_key_jwt,
     * client_secret_basic/post and public clients) rather than the league default that requires a client_id
     * request parameter.
     *
     * @throws \ReflectionException
     */
    public function testValidateClientResolvesClientWithoutRequiringClientIdParameter(): void
    {
        $clientMock = $this->createMock(ClientEntity::class);
        $this->clientResolverMock->expects($this->once())
            ->method('forAnySupportedMethod')
            ->with($this->serverRequestMock)
            ->willReturn(new ResolvedClientAuthenticationMethod(
                $clientMock,
                ClientAuthenticationMethodsEnum::PrivateKeyJwt,
            ));

        $this->assertSame($clientMock, $this->callValidateClient($this->sut()));
        $this->assertSame([], $this->emittedEventNames);
    }


    /**
     * When the client cannot be authenticated the grant must reject the request with an invalid_client error,
     * not fall back to the league default (which would demand a client_id parameter). The failure is both
     * logged and announced on the emitter, which is what a listener registered on the server would count.
     *
     * @throws \ReflectionException
     */
    public function testValidateClientThrowsWhenClientCannotBeResolved(): void
    {
        $this->clientResolverMock->expects($this->once())
            ->method('forAnySupportedMethod')
            ->with($this->serverRequestMock)
            ->willReturn(null);

        $this->loggerServiceMock->expects($this->once())
            ->method('warning')
            ->with($this->stringContains('client authentication failed'));

        $this->expectException(OAuthServerException::class);

        try {
            $this->callValidateClient($this->sut());
        } finally {
            $this->assertSame([RequestEvent::CLIENT_AUTHENTICATION_FAILED], $this->emittedEventNames);
        }
    }


    /**
     * league answers a missing `refresh_token` with `invalid_request`; this answers with `invalid_grant`.
     * The league parameter parser trims the value and treats an empty result as absent, so a blank or
     * whitespace-only parameter arrives here as null and takes the same path -- there is no separate
     * "present but empty" rejection to write.
     *
     * @param array<string, mixed> $parsedBody
     * @throws \ReflectionException
     */
    #[DataProvider('absentRefreshTokenProvider')]
    public function testRejectsARequestWhichCarriesNoRefreshToken(array $parsedBody): void
    {
        $this->loggerServiceMock->expects($this->once())
            ->method('notice')
            ->with(
                'Refresh token request rejected: `refresh_token` parameter not provided.',
                ['client_id' => self::CLIENT_ID],
            );
        $this->loggerServiceMock->expects($this->never())->method('warning');

        $exception = $this->rejectionOf($this->sut(), $parsedBody);

        $this->assertSame('invalid_grant', $exception->getErrorType());
        $this->assertSame('Failed to verify `refresh_token`', $exception->getHint());
        $this->assertSame(400, $exception->getHttpStatusCode());
        $this->assertSame([], $this->emittedEventNames);
    }


    /**
     * @return array<string, array{0: array<string, mixed>}>
     */
    public static function absentRefreshTokenProvider(): array
    {
        return [
            'no parameter at all' => [[]],
            'an empty string' => [['refresh_token' => '']],
            'whitespace only' => [['refresh_token' => " \t "]],
        ];
    }


    /**
     * Everything CryptTrait raises descends from Exception, so all three of these -- a value which is not
     * ciphertext at all, ciphertext from another key, and a grant whose key was never configured -- land in
     * the same catch and become the same protocol error, with the underlying failure kept as `previous`.
     *
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     * @throws \ReflectionException
     */
    #[DataProvider('undecryptableRefreshTokenProvider')]
    public function testRejectsARefreshTokenItCannotDecrypt(string $refreshToken, bool $withEncryptionKey): void
    {
        $this->loggerServiceMock->expects($this->once())
            ->method('warning')
            ->with(
                'Refresh token request rejected: could not decrypt the refresh token.',
                $this->callback(fn(array $context): bool => $context['client_id'] === self::CLIENT_ID
                    && is_string($context['exception'])),
            );

        $exception = $this->rejectionOf(
            $this->sut(withEncryptionKey: $withEncryptionKey),
            ['refresh_token' => $refreshToken],
        );

        $this->assertSame('invalid_grant', $exception->getErrorType());
        $this->assertSame('Cannot decrypt the refresh token', $exception->getHint());
        $this->assertNotNull($exception->getPrevious());
        $this->assertSame([], $this->emittedEventNames);
    }


    /**
     * @return array<string, array{0: string, 1: bool}>
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     * @throws \JsonException
     */
    public static function undecryptableRefreshTokenProvider(): array
    {
        return [
            'not ciphertext at all' => ['this-is-not-a-refresh-token', true],
            'ciphertext from another key' => [
                Crypto::encrypt(
                    json_encode(self::refreshTokenPayload(), JSON_THROW_ON_ERROR),
                    Key::createNewRandomKey(),
                ),
                true,
            ],
            'no encryption key configured' => [self::encryptedPayload(self::refreshTokenPayload()), false],
        ];
    }


    /**
     * league decodes the payload and indexes straight into it. This checks the decoded type first, so a
     * payload which is valid JSON but not an object becomes a protocol error here where league would reach
     * for `client_id` on a scalar.
     *
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     * @throws \ReflectionException
     */
    #[DataProvider('nonArrayPayloadProvider')]
    public function testRejectsADecryptedPayloadWhichIsNotAnArray(string $json): void
    {
        $this->loggerServiceMock->expects($this->once())
            ->method('warning')
            ->with(
                'Refresh token request rejected: decrypted refresh token has an unexpected type.',
                ['client_id' => self::CLIENT_ID],
            );

        $exception = $this->rejectionOf($this->sut(), ['refresh_token' => self::encryptedString($json)]);

        $this->assertSame('invalid_grant', $exception->getErrorType());
        $this->assertSame('Refresh token has unexpected type', $exception->getHint());
        $this->assertSame([], $this->emittedEventNames);
    }


    /**
     * @return array<string, array{0: string}>
     */
    public static function nonArrayPayloadProvider(): array
    {
        return [
            'a number' => ['123'],
            'a string' => ['"a-refresh-token"'],
            'a boolean' => ['true'],
            'a JSON null' => ['null'],
        ];
    }


    /**
     * The payload is decoded with JSON_THROW_ON_ERROR, so a decryptable but malformed payload leaves this
     * method as a JsonException: the one rejection here which is neither logged nor turned into a 400. Only
     * a payload this deployment encrypted itself can reach it, so a server error is the honest answer, but
     * it is worth pinning -- it is the difference between the caller seeing invalid_grant and seeing a 500.
     *
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     * @throws \ReflectionException
     */
    public function testAMalformedPayloadRaisesAJsonExceptionAndIsNotLogged(): void
    {
        $this->loggerServiceMock->expects($this->never())->method('notice');
        $this->loggerServiceMock->expects($this->never())->method('warning');
        $this->loggerServiceMock->expects($this->never())->method('error');

        $this->expectException(JsonException::class);

        $this->callValidateOldRefreshToken(
            $this->sut(),
            ['refresh_token' => self::encryptedString('{"client_id": ')],
        );
    }


    /**
     * A refresh token is bound to the client it was issued to, and that binding is what makes it safe for
     * the grant to authenticate the caller without a `client_id` parameter. The mismatch is the only one
     * of this method's rejections announced on the emitter.
     *
     * @param array<string, mixed> $payload
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     * @throws \ReflectionException
     */
    #[DataProvider('mismatchedClientPayloadProvider')]
    public function testRejectsARefreshTokenIssuedToAnotherClient(array $payload, ?string $loggedTokenId): void
    {
        $this->loggerServiceMock->expects($this->once())
            ->method('warning')
            ->with(
                'Refresh token request rejected: refresh token is not linked to the authenticated client.',
                [
                    'client_id' => self::CLIENT_ID,
                    'refresh_token_client_id' => self::OTHER_CLIENT_ID,
                    'refresh_token_id' => $loggedTokenId,
                ],
            );

        $exception = $this->rejectionOf($this->sut(), ['refresh_token' => self::encryptedPayload($payload)]);

        $this->assertSame('invalid_grant', $exception->getErrorType());
        $this->assertSame('Refresh token is not linked to client', $exception->getHint());
        $this->assertSame([RequestEvent::REFRESH_TOKEN_CLIENT_FAILED], $this->emittedEventNames);
    }


    /**
     * @return array<string, array{0: array<string, mixed>, 1: string|null}>
     */
    public static function mismatchedClientPayloadProvider(): array
    {
        $payload = self::refreshTokenPayload(['client_id' => self::OTHER_CLIENT_ID]);

        return [
            'a payload carrying its own token id' => [$payload, self::REFRESH_TOKEN_ID],
            // The log line reaches for refresh_token_id defensively. A payload without one still has to be
            // rejected and logged rather than fatal on the missing key.
            'a payload without one' => [array_diff_key($payload, ['refresh_token_id' => null]), null],
        ];
    }


    /**
     * The expiry rejection reaches for refresh_token_id defensively, exactly as the client mismatch does,
     * so a payload stripped of it has to be rejected and logged rather than fatal on the missing key.
     * Note what this row does not do: dropping the `?? null` would not fail it, because an undefined key
     * is a warning rather than an error in PHP 8 and the logged value is null either way. What it pins is
     * that such a payload is still rejected and still logged, not the operator which keeps it quiet.
     *
     * @param array<string, mixed> $payload
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     * @throws \ReflectionException
     */
    #[DataProvider('expiredPayloadProvider')]
    public function testRejectsAnExpiredRefreshToken(array $payload, ?string $loggedTokenId): void
    {
        $this->loggerServiceMock->expects($this->once())
            ->method('notice')
            ->with(
                'Refresh token request rejected: refresh token has expired.',
                ['client_id' => self::CLIENT_ID, 'refresh_token_id' => $loggedTokenId],
            );
        $this->loggerServiceMock->expects($this->never())->method('warning');

        $exception = $this->rejectionOf($this->sut(), ['refresh_token' => self::encryptedPayload($payload)]);

        $this->assertSame('invalid_grant', $exception->getErrorType());
        $this->assertSame('Refresh token has expired', $exception->getHint());
        $this->assertSame([], $this->emittedEventNames);
    }


    /**
     * @return array<string, array{0: array<string, mixed>, 1: string|null}>
     */
    public static function expiredPayloadProvider(): array
    {
        $payload = self::refreshTokenPayload(['expire_time' => time() - 1]);

        return [
            'a payload carrying its own token id' => [$payload, self::REFRESH_TOKEN_ID],
            'a payload without one' => [array_diff_key($payload, ['refresh_token_id' => null]), null],
        ];
    }


    /**
     * The check is `expire_time < time()`, so a token whose last second is the current one is still valid.
     * This test exists for that one boundary: only an exact equality distinguishes `<` from `<=`. Removing
     * or inverting the guard is caught by testRejectsAnExpiredRefreshToken instead, which is why this one
     * asserts acceptance and nothing more. The clock can turn over while the call runs, which would prove
     * nothing either way, so a run which straddled two seconds is discarded and retried rather than
     * asserted on.
     *
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     * @throws \ReflectionException
     */
    public function testARefreshTokenExpiringInTheCurrentSecondIsNotYetExpired(): void
    {
        $this->refreshTokenRepositoryMock->method('isRefreshTokenRevoked')->willReturn(false);

        for ($attempt = 1; $attempt <= 5; $attempt++) {
            $second = time();
            $payload = self::refreshTokenPayload(['expire_time' => $second]);

            try {
                $outcome = $this->callValidateOldRefreshToken(
                    $this->sut(),
                    ['refresh_token' => self::encryptedPayload($payload)],
                );
            } catch (OidcServerException $exception) {
                $outcome = $exception;
            }

            if (time() !== $second) {
                continue;
            }

            $this->assertSame(
                $payload,
                $outcome,
                'A refresh token whose expire_time is the current second was rejected as expired.',
            );

            return;
        }

        $this->fail('The clock crossed a second boundary on every attempt.');
    }


    /**
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     * @throws \ReflectionException
     */
    public function testRejectsARevokedRefreshToken(): void
    {
        $this->refreshTokenRepositoryMock->expects($this->once())
            ->method('isRefreshTokenRevoked')
            ->with(self::REFRESH_TOKEN_ID)
            ->willReturn(true);

        $this->loggerServiceMock->expects($this->once())
            ->method('warning')
            ->with(
                'Refresh token request rejected: refresh token has been revoked.',
                ['client_id' => self::CLIENT_ID, 'refresh_token_id' => self::REFRESH_TOKEN_ID],
            );

        $exception = $this->rejectionOf(
            $this->sut(),
            ['refresh_token' => self::encryptedPayload(self::refreshTokenPayload())],
        );

        $this->assertSame('invalid_grant', $exception->getErrorType());
        $this->assertSame('Refresh token has been revoked', $exception->getHint());
        $this->assertSame([], $this->emittedEventNames);
    }


    /**
     * The revocation lookup takes a string, and league hands the decoded value over as it found it. A
     * numeric token id therefore reaches the repository as an int there, which under the grant's own
     * `strict_types` is a TypeError at the call rather than a lookup -- the cast is what keeps a numeric
     * id a refusable token instead of a 500.
     *
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     * @throws \ReflectionException
     */
    public function testPassesTheRefreshTokenIdToTheRepositoryAsAString(): void
    {
        $this->refreshTokenRepositoryMock->expects($this->once())
            ->method('isRefreshTokenRevoked')
            ->with($this->identicalTo('1234567890'))
            ->willReturn(false);

        $payload = self::refreshTokenPayload(['refresh_token_id' => 1234567890]);

        $this->assertSame(
            $payload,
            $this->callValidateOldRefreshToken($this->sut(), ['refresh_token' => self::encryptedPayload($payload)]),
        );
    }


    /**
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     * @throws \ReflectionException
     */
    public function testReturnsTheDecodedPayloadForAValidRefreshToken(): void
    {
        $this->refreshTokenRepositoryMock->expects($this->once())
            ->method('isRefreshTokenRevoked')
            ->with(self::REFRESH_TOKEN_ID)
            ->willReturn(false);

        $this->loggerServiceMock->expects($this->never())->method('notice');
        $this->loggerServiceMock->expects($this->never())->method('warning');

        $payload = self::refreshTokenPayload();

        $this->assertSame(
            $payload,
            $this->callValidateOldRefreshToken($this->sut(), ['refresh_token' => self::encryptedPayload($payload)]),
        );
        $this->assertSame([], $this->emittedEventNames);
    }


    /**
     * Every rejection this method raises writes a log line, and the refresh token is the credential the
     * request is made of. None of those lines may carry the encrypted token or the decrypted payload
     * itself: a log file is read by more people than a token store is, and a refresh token is replayable
     * until it is revoked. The token id is logged deliberately and is not what this bans -- it identifies
     * the token without being usable as one. The five rows here are the rejections which have a token to
     * leak in the first place.
     *
     * The captured calls are flattened with print_r rather than json_encode, because a JSON encoder would
     * escape a leaked payload's quotes and slashes and the assertion would then look right while matching
     * nothing.
     *
     * Every rejection is covered here, because the token arrives on all of them.
     *
     * @throws \ReflectionException
     */
    #[DataProvider('rejectedRefreshTokenProvider')]
    public function testNoRejectionPathLogsTheEncryptedRefreshToken(string $refreshToken, bool $isRevoked): void
    {
        $this->refreshTokenRepositoryMock->method('isRefreshTokenRevoked')->willReturn($isRevoked);
        $this->captureLogCalls();

        $this->rejectionOf($this->sut(), ['refresh_token' => $refreshToken]);

        $this->assertNotEmpty($this->logCalls, 'The rejection was not logged at all.');
        $this->assertStringNotContainsString($refreshToken, print_r($this->logCalls, true));
    }


    /**
     * @return array<string, array{0: string, 1: bool}>
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     * @throws \JsonException
     */
    public static function rejectedRefreshTokenProvider(): array
    {
        $valid = json_encode(self::refreshTokenPayload(), JSON_THROW_ON_ERROR);

        return [
            // Ciphertext under a key this grant does not hold: what a token from another deployment, or from
            // before a key rotation, looks like on the wire.
            'undecryptable' => [Crypto::encrypt($valid, Key::createNewRandomKey()), false],
            'not an array' => [self::encryptedString('"a-secret-refresh-payload"'), false],
            'another client' => [
                self::encryptedPayload(self::refreshTokenPayload(['client_id' => self::OTHER_CLIENT_ID])),
                false,
            ],
            'expired' => [
                self::encryptedPayload(self::refreshTokenPayload(['expire_time' => time() - 1])),
                false,
            ],
            'revoked' => [self::encryptedPayload(self::refreshTokenPayload()), true],
        ];
    }


    /**
     * The other half: the payload behind the token. It leaks in two shapes and both are checked, because
     * they are caught by different assertions -- logging the decrypted string would show the serialised
     * form, while logging the decoded array would render its fields and show only the values.
     *
     * The two field values checked are the ones with nothing to say for themselves in a log, the access
     * token id and the user id. `client_id` and `refresh_token_id` are logged deliberately and are not what
     * this bans.
     *
     * Only the rejections which get as far as a decoded payload are listed. The undecryptable token never
     * yields one, and the non-array payload has no fields, so asserting either of those here would be
     * asserting that the grant did not log something it never held.
     *
     * @throws \ReflectionException
     */
    #[DataProvider('decodedPayloadRejectionProvider')]
    public function testNoRejectionPathLogsTheDecryptedPayload(
        string $refreshToken,
        string $payload,
        bool $isRevoked,
    ): void {
        $this->refreshTokenRepositoryMock->method('isRefreshTokenRevoked')->willReturn($isRevoked);
        $this->captureLogCalls();

        $this->rejectionOf($this->sut(), ['refresh_token' => $refreshToken]);

        $written = print_r($this->logCalls, true);

        $this->assertStringNotContainsString($payload, $written);
        $this->assertStringNotContainsString(self::ACCESS_TOKEN_ID, $written);
        $this->assertStringNotContainsString(self::USER_ID, $written);
    }


    /**
     * @return array<string, array{0: string, 1: string, 2: bool}>
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     * @throws \JsonException
     */
    public static function decodedPayloadRejectionProvider(): array
    {
        $mismatched = json_encode(
            self::refreshTokenPayload(['client_id' => self::OTHER_CLIENT_ID]),
            JSON_THROW_ON_ERROR,
        );
        $expired = json_encode(self::refreshTokenPayload(['expire_time' => time() - 1]), JSON_THROW_ON_ERROR);
        $valid = json_encode(self::refreshTokenPayload(), JSON_THROW_ON_ERROR);

        return [
            'another client' => [self::encryptedString($mismatched), $mismatched, false],
            'expired' => [self::encryptedString($expired), $expired, false],
            'revoked' => [self::encryptedString($valid), $valid, true],
        ];
    }


    /**
     * Of this method's rejections only the client mismatch is announced on the emitter -- `validateClient()`
     * announces its own failure separately, under a different event. A deployment counting
     * REFRESH_TOKEN_CLIENT_FAILED is counting tokens presented by the wrong client, so a rejection which
     * quietly joined that count would misreport what it measures.
     *
     * @param string[] $expectedEvents
     * @throws \ReflectionException
     */
    #[DataProvider('rejectionEventProvider')]
    public function testOnlyAClientMismatchIsAnnouncedOnTheEmitter(
        string $refreshToken,
        bool $isRevoked,
        array $expectedEvents,
    ): void {
        $this->refreshTokenRepositoryMock->method('isRefreshTokenRevoked')->willReturn($isRevoked);

        $this->rejectionOf($this->sut(), ['refresh_token' => $refreshToken]);

        $this->assertSame($expectedEvents, $this->emittedEventNames);
    }


    /**
     * @return array<string, array{0: string, 1: bool, 2: string[]}>
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     * @throws \JsonException
     */
    public static function rejectionEventProvider(): array
    {
        return [
            'undecryptable' => ['not-a-refresh-token', false, []],
            'not an array' => [self::encryptedString('"a-refresh-token"'), false, []],
            'another client' => [
                self::encryptedPayload(self::refreshTokenPayload(['client_id' => self::OTHER_CLIENT_ID])),
                false,
                [RequestEvent::REFRESH_TOKEN_CLIENT_FAILED],
            ],
            'expired' => [
                self::encryptedPayload(self::refreshTokenPayload(['expire_time' => time() - 1])),
                false,
                [],
            ],
            'revoked' => [self::encryptedPayload(self::refreshTokenPayload()), true, []],
        ];
    }


    /**
     * The grant reconstructs the old token's issue time as its expiry less the grant's own refresh token
     * TTL, and waits a second when that lands on the current second, so that a refreshed ID Token cannot
     * carry the same `iat` as the one it replaces. A token issued at any other moment must not pay for it.
     * What this catches is a delay which stopped being conditional; a delay which stopped happening at all
     * is caught by the test below it. A loaded machine can descheduled this process for a second without
     * the grant having slept at all, so a slow run is retried; an unconditional delay is slow every time.
     *
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     * @throws \ReflectionException
     */
    public function testDoesNotDelayWhenTheOldTokenWasNotIssuedInTheCurrentSecond(): void
    {
        $this->refreshTokenRepositoryMock->method('isRefreshTokenRevoked')->willReturn(false);

        $elapsed = 1.0;

        for ($attempt = 1; $attempt <= 3 && $elapsed >= 1.0; $attempt++) {
            $payload = self::refreshTokenPayload(['expire_time' => time() + 300]);
            $startedAt = microtime(true);

            $this->callValidateOldRefreshToken(
                $this->sut(new DateInterval('PT10M')),
                ['refresh_token' => self::encryptedPayload($payload)],
            );

            $elapsed = microtime(true) - $startedAt;
        }

        $this->assertLessThan(1.0, $elapsed, 'The refresh was delayed where it had no reason to be.');
    }


    /**
     * The other side of it: a token whose expiry is exactly one TTL away was issued in this very second, so
     * the grant waits before letting the refresh proceed. Whether it waited is observable only as elapsed
     * time, and the second can turn over between building the fixture and the grant reading the clock, so a
     * run which did not wait is retried rather than failed.
     *
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     * @throws \ReflectionException
     */
    public function testDelaysASecondWhenTheOldTokenWasIssuedInTheCurrentSecond(): void
    {
        $this->refreshTokenRepositoryMock->method('isRefreshTokenRevoked')->willReturn(false);

        $elapsed = 0.0;

        for ($attempt = 1; $attempt <= 3 && $elapsed < 1.0; $attempt++) {
            $payload = self::refreshTokenPayload(['expire_time' => time() + 600]);
            $startedAt = microtime(true);

            $this->callValidateOldRefreshToken(
                $this->sut(new DateInterval('PT10M')),
                ['refresh_token' => self::encryptedPayload($payload)],
            );

            $elapsed = microtime(true) - $startedAt;
        }

        $this->assertGreaterThanOrEqual(
            1.0,
            $elapsed,
            'A refresh token reconstructed as issued in the current second was not delayed.',
        );
    }


    /**
     * The league signature this overrides is typed on league's own access token interface, which is wider
     * than the module's. The issuer needs the module's, so the grant refuses anything else rather than
     * handing it on.
     *
     * @throws \ReflectionException
     */
    public function testIssueRefreshTokenRejectsAnAccessTokenOfTheWrongType(): void
    {
        $this->refreshTokenIssuerMock->expects($this->never())->method('issue');

        try {
            $this->callIssueRefreshToken($this->sut(), $this->createMock(OAuth2AccessTokenEntityInterface::class));
            $this->fail('An access token of the wrong type was accepted.');
        } catch (OidcServerException $exception) {
            $this->assertSame('server_error', $exception->getErrorType());
            $this->assertSame(500, $exception->getHttpStatusCode());
            $this->assertStringContainsString('Unexpected access token entity type.', $exception->getMessage());
        }
    }


    /**
     * The TTL is asserted by identity, so passing an equal-but-different interval would not satisfy it: the
     * point is that the issuer is given the grant's own configured TTL. The attempt limit is asserted by
     * value because the two constants differ -- the grant passes AbstractGrant's ten where the issuer's own
     * default is five -- so dropping the argument would quietly halve the retries.
     *
     * @throws \ReflectionException
     */
    #[DataProvider('authCodeIdProvider')]
    public function testIssueRefreshTokenDelegatesToTheIssuer(?string $authCodeId): void
    {
        $accessToken = $this->createMock(AccessTokenEntityInterface::class);
        $refreshToken = $this->createMock(RefreshTokenEntityInterface::class);
        $refreshTokenTtl = new DateInterval('PT2H');

        $this->refreshTokenIssuerMock->expects($this->once())
            ->method('issue')
            ->with($accessToken, $this->identicalTo($refreshTokenTtl), $authCodeId, 10)
            ->willReturn($refreshToken);

        $this->assertSame(
            $refreshToken,
            $this->callIssueRefreshToken($this->sut($refreshTokenTtl), $accessToken, $authCodeId),
        );
    }


    /**
     * @return array<string, array{0: string|null}>
     */
    public static function authCodeIdProvider(): array
    {
        return [
            'issued against an authorization code' => ['auth-code-id'],
            'issued without one' => [null],
        ];
    }


    /**
     * The signature permits a null, and league's respondToAccessTokenRequest() reads one as "no refresh
     * token in the response" rather than as a failure, so the grant must pass it on rather than treat it as
     * an error. The issuer cannot currently produce one: its `return null` sits after a loop which rethrows
     * on the last attempt, unreachable at any positive attempt limit for exactly the reason the trait's own
     * unreachable throw is described below, and this grant always passes ten. So what this pins is the
     * pass-through, not a state production reaches today.
     *
     * @throws \ReflectionException
     */
    public function testIssueRefreshTokenReturnsNullWhenTheIssuerDeclines(): void
    {
        $this->refreshTokenIssuerMock->expects($this->once())->method('issue')->willReturn(null);

        $this->assertNull(
            $this->callIssueRefreshToken($this->sut(), $this->createMock(AccessTokenEntityInterface::class)),
        );
    }


    /**
     * The league setter accepts league's access token repository interface, which is wider than the one
     * IssueAccessTokenTrait declares it needs, so a repository can satisfy the setter and still be the
     * wrong thing. Nothing on this path actually calls a method the narrower interface adds -- only
     * persistNewAccessToken(), which both declare -- so the guard states an expectation rather than
     * standing in for a missing method.
     *
     * @throws \ReflectionException
     */
    public function testIssueAccessTokenRejectsARepositoryWhichIsNotTheModulesOwn(): void
    {
        $grant = $this->sut();
        $grant->setAccessTokenRepository($this->createMock(OAuth2AccessTokenRepositoryInterface::class));

        $this->accessTokenEntityFactoryMock->expects($this->never())->method('fromData');

        try {
            $this->callIssueAccessToken($grant, new DateInterval('PT15M'), $this->createMock(ClientEntity::class));
            $this->fail('A repository which is not the module\'s own was accepted.');
        } catch (OidcServerException $exception) {
            $this->assertSame('server_error', $exception->getErrorType());
            $this->assertSame(500, $exception->getHttpStatusCode());
            $this->assertStringContainsString(AccessTokenRepositoryInterface::class, $exception->getMessage());
        }
    }


    /**
     * @throws \ReflectionException
     */
    public function testIssueAccessTokenPersistsAndReturnsTheToken(): void
    {
        $client = $this->createMock(ClientEntity::class);
        $accessToken = $this->createMock(AccessTokenEntity::class);
        $repository = $this->createMock(AccessTokenRepositoryInterface::class);
        // Scopes have to be a value the helper did not also supply as the parameter's own default, or the
        // assertion below could not tell a forwarded argument from a defaulted one.
        $scopes = [
            $this->createMock(ScopeEntityInterface::class),
            $this->createMock(ScopeEntityInterface::class),
        ];

        $this->accessTokenEntityFactoryMock->expects($this->once())
            ->method('fromData')
            ->willReturnCallback(function (mixed ...$arguments) use ($accessToken): AccessTokenEntity {
                $this->accessTokenFactoryArguments[] = $arguments;

                return $accessToken;
            });

        $repository->expects($this->once())->method('persistNewAccessToken')->with($accessToken);

        $grant = $this->sut();
        $grant->setAccessTokenRepository($repository);

        $this->assertSame(
            $accessToken,
            $this->callIssueAccessToken($grant, new DateInterval('PT25M'), $client, $scopes),
        );

        $arguments = $this->accessTokenFactoryArguments[0];
        [$identifier, $passedClient, $passedScopes, $expiryDateTime, $userIdentifier] = $arguments;

        $this->assertNotSame('', $identifier);
        $this->assertSame($client, $passedClient);
        $this->assertSame($scopes, $passedScopes);
        $this->assertSame(self::USER_ID, $userIdentifier);
        $this->assertInstanceOf(DateTimeImmutable::class, $expiryDateTime);
        $this->assertEqualsWithDelta(time() + 1500, $expiryDateTime->getTimestamp(), 5);
    }


    /**
     * A duplicate identifier is a collision in the token store, not a failed request, so the trait tries
     * again with a freshly generated one. Reusing the identifier which just collided would loop to the
     * attempt limit and fail every time.
     *
     * @throws \ReflectionException
     */
    public function testIssueAccessTokenRetriesWithAFreshIdentifierAfterACollision(): void
    {
        $accessToken = $this->createMock(AccessTokenEntity::class);
        $repository = $this->createMock(AccessTokenRepositoryInterface::class);
        $attempts = 0;

        $this->accessTokenEntityFactoryMock->expects($this->exactly(2))
            ->method('fromData')
            ->willReturnCallback(function (mixed ...$arguments) use ($accessToken): AccessTokenEntity {
                $this->accessTokenFactoryArguments[] = $arguments;

                return $accessToken;
            });

        $repository->expects($this->exactly(2))
            ->method('persistNewAccessToken')
            ->willReturnCallback(function () use (&$attempts): void {
                if (++$attempts === 1) {
                    throw UniqueTokenIdentifierConstraintViolationException::create();
                }
            });

        $grant = $this->sut();
        $grant->setAccessTokenRepository($repository);

        $this->assertSame(
            $accessToken,
            $this->callIssueAccessToken($grant, new DateInterval('PT15M'), $this->createMock(ClientEntity::class)),
        );

        $this->assertNotSame(
            $this->accessTokenFactoryArguments[0][0],
            $this->accessTokenFactoryArguments[1][0],
            'The retry reused the identifier which had just collided.',
        );
    }


    /**
     * The loop is bounded by AbstractGrant::MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS, which is ten, and on the
     * last attempt the catch rethrows rather than letting the loop end. That makes the
     * `Unable to issue Access Token.` throw underneath it unreachable: the counter can only reach zero
     * inside the catch, and `self::` binds the constant to this class, so no subclass can lower it. The
     * throw stays because the method has to terminate, and it is the trait's one uncovered statement.
     *
     * @throws \ReflectionException
     */
    public function testIssueAccessTokenGivesUpAfterTenCollisions(): void
    {
        $repository = $this->createMock(AccessTokenRepositoryInterface::class);

        $this->accessTokenEntityFactoryMock->expects($this->exactly(10))
            ->method('fromData')
            ->willReturnCallback(function (mixed ...$arguments): AccessTokenEntity {
                $this->accessTokenFactoryArguments[] = $arguments;

                return $this->createMock(AccessTokenEntity::class);
            });

        $repository->expects($this->exactly(10))
            ->method('persistNewAccessToken')
            ->willThrowException(UniqueTokenIdentifierConstraintViolationException::create());

        $grant = $this->sut();
        $grant->setAccessTokenRepository($repository);

        $this->expectException(UniqueTokenIdentifierConstraintViolationException::class);

        $this->callIssueAccessToken($grant, new DateInterval('PT15M'), $this->createMock(ClientEntity::class));
    }
}
