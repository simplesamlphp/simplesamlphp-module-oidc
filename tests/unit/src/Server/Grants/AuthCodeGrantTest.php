<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\Grants;

use Closure;
use DateInterval;
use DateTimeImmutable;
use Defuse\Crypto\Key;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface as OAuth2AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\AuthCodeEntity;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\RefreshTokenEntityInterface;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\Factories\Entities\AccessTokenEntityFactory;
use SimpleSAML\Module\oidc\Factories\Entities\AuthCodeEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Helpers\Scope;
use SimpleSAML\Module\oidc\Repositories\AuthCodeRepository;
use SimpleSAML\Module\oidc\Repositories\Interfaces\AccessTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Repositories\Interfaces\RefreshTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Server\Grants\AuthCodeGrant;
use SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientAuthenticationRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\CodeVerifierRule;
use SimpleSAML\Module\oidc\Server\ResponseTypes\Interfaces\AcrResponseTypeInterface;
use SimpleSAML\Module\oidc\Server\ResponseTypes\Interfaces\AuthTimeResponseTypeInterface;
use SimpleSAML\Module\oidc\Server\ResponseTypes\Interfaces\NonceResponseTypeInterface;
use SimpleSAML\Module\oidc\Server\ResponseTypes\Interfaces\SessionIdResponseTypeInterface;
use SimpleSAML\Module\oidc\Server\TokenIssuers\RefreshTokenIssuer;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Module\oidc\ValueAbstracts\ResolvedClientAuthenticationMethod;
use SimpleSAML\OpenID\Codebooks\ClientAuthenticationMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;
use Stringable;

/**
 * Token endpoint behavior of the authorization code grant.
 *
 * Covers the code redemption half of the grant: everything reachable from respondToAccessTokenRequest(),
 * including validateAuthorizationCode(). The authorization request half
 * (validateAuthorizationRequestWithRequestRules(), completeOidcAuthorizationRequest()) is not covered here.
 *
 * Most of what this class does on redemption is reject things, and each rejection is a security control:
 * PKCE verification, the redirect URI and client bindings, authorization code expiry and replay. Those are
 * asserted on the error type the client actually receives, because the error type is the protocol-visible
 * contract, not the message text.
 */
#[CoversClass(AuthCodeGrant::class)]
#[UsesClass(AuthCodeEntity::class)]
#[UsesClass(ResultBag::class)]
#[UsesClass(Result::class)]
#[UsesClass(ScopeEntity::class)]
#[UsesClass(ResolvedClientAuthenticationMethod::class)]
class AuthCodeGrantTest extends TestCase
{
    private const string AUTH_CODE_ID = 'auth-code-id';
    private const string CLIENT_ID = 'client-id';
    private const string USER_ID = 'user-id';
    private const string REDIRECT_URI = 'https://rp.example.org/callback';
    private const string CODE_VERIFIER = 'ZG9uLXQtdXNlLXRoaXMtdmVyaWZpZXItaW4tcHJvZHVjdGlvbg';

    private AuthCodeRepository&MockObject $authCodeRepositoryMock;
    private AccessTokenRepositoryInterface&MockObject $accessTokenRepositoryMock;
    private RefreshTokenRepositoryInterface&MockObject $refreshTokenRepositoryMock;
    private RequestRulesManager&MockObject $requestRulesManagerMock;
    private RequestParamsResolver&MockObject $requestParamsResolverMock;
    private AccessTokenEntityFactory&MockObject $accessTokenEntityFactoryMock;
    private AuthCodeEntityFactory&MockObject $authCodeEntityFactoryMock;
    private RefreshTokenIssuer&MockObject $refreshTokenIssuerMock;
    private Helpers&MockObject $helpersMock;
    private Scope&MockObject $scopeHelperMock;
    private LoggerService&MockObject $loggerServiceMock;
    private ScopeRepositoryInterface&MockObject $scopeRepositoryMock;

    private Key $encryptionKey;

    /** Whether the granted scopes are treated as containing offline_access. */
    private bool $offlineAccessGranted = false;

    /** @var array<int,array{message:string,context:array}> */
    private array $logRecords = [];

    protected function setUp(): void
    {
        $this->authCodeRepositoryMock = $this->createMock(AuthCodeRepository::class);
        $this->accessTokenRepositoryMock = $this->createMock(AccessTokenRepositoryInterface::class);
        $this->refreshTokenRepositoryMock = $this->createMock(RefreshTokenRepositoryInterface::class);
        $this->requestRulesManagerMock = $this->createMock(RequestRulesManager::class);
        $this->requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $this->accessTokenEntityFactoryMock = $this->createMock(AccessTokenEntityFactory::class);
        $this->authCodeEntityFactoryMock = $this->createMock(AuthCodeEntityFactory::class);
        $this->refreshTokenIssuerMock = $this->createMock(RefreshTokenIssuer::class);
        $this->helpersMock = $this->createMock(Helpers::class);
        $this->scopeHelperMock = $this->createMock(Scope::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        $this->scopeRepositoryMock = $this->createMock(ScopeRepositoryInterface::class);

        // A Key rather than a password string: both are accepted by the grant, but the password form runs a
        // key derivation on every encrypt and decrypt, which this many round trips would make noticeably slow.
        $this->encryptionKey = Key::createNewRandomKey();

        $this->helpersMock->method('scope')->willReturn($this->scopeHelperMock);
        $this->scopeHelperMock->method('exists')->willReturnCallback(fn(): bool => $this->offlineAccessGranted);

        $this->scopeRepositoryMock->method('getScopeEntityByIdentifier')
            ->willReturnCallback(static fn(string $identifier): ScopeEntity => new ScopeEntity($identifier));
        $this->scopeRepositoryMock->method('finalizeScopes')
            ->willReturnCallback(static fn(array $scopes): array => $scopes);

        $this->resolverReturnsTheRequestBody($this->requestParamsResolverMock);

        $this->captureLogs('debug');
        $this->captureLogs('info');
        $this->captureLogs('notice');
        $this->captureLogs('warning');
        $this->captureLogs('error');
    }

    // Authorization code intake.

    public function testRejectsTokenRequestWithoutAuthorizationCode(): void
    {
        $this->assertRejects(
            'invalid_request',
            $this->request([]),
        );
    }

    public function testRejectsAuthorizationCodeItCannotDecrypt(): void
    {
        // A code encrypted under a different key stands in for any tampered or forged code. The grant must
        // answer with a protocol error rather than letting the decryption failure escape as a 500.
        $foreignKey = Key::createNewRandomKey();

        $this->assertRejects(
            'invalid_request',
            $this->request(['code' => $this->encryptPayload($this->payload(), $foreignKey)]),
        );
    }

    public function testRejectsAuthorizationCodePayloadWithoutIdentifier(): void
    {
        $this->authCodeRepositoryMock->expects($this->never())->method('findById');

        $this->assertRejects(
            'invalid_request',
            $this->request(['code' => $this->encryptPayload(['client_id' => self::CLIENT_ID])]),
        );
    }

    public function testRejectsAuthorizationCodeThatIsNotInStorage(): void
    {
        $this->authCodeRepositoryMock->method('findById')->willReturn(null);

        $this->assertRejects('invalid_grant', $this->request());
    }

    public function testRejectsUnexpectedAuthCodeRepositoryType(): void
    {
        // The grant is constructed against the league interface but reaches for this module's repository, so
        // a foreign implementation has to be refused rather than fatal on the first extra method call.
        $foreignRepository = $this->createMock(OAuth2AuthCodeRepositoryInterface::class);

        $this->assertRejects(
            'server_error',
            $this->request(),
            $this->sut($foreignRepository),
        );
    }

    // Binding checks for generic (non-registered) clients, which have no credential to authenticate with.

    public function testRequiresClientIdFromGenericClient(): void
    {
        $this->storedAuthCode(isGeneric: true);
        $this->resolveRequestParams(clientId: null);

        $this->assertRejects('invalid_request', $this->request());
    }

    public function testRejectsClientIdThatDoesNotMatchTheBoundOne(): void
    {
        $this->storedAuthCode(isGeneric: true);
        $this->resolveRequestParams(clientId: 'some-other-client');

        $this->assertRejects('invalid_grant', $this->request());
    }

    public function testRequiresRedirectUriFromGenericClient(): void
    {
        $this->storedAuthCode(isGeneric: true);
        $this->resolveRequestParams(redirectUri: null);

        $this->assertRejects('invalid_request', $this->request());
    }

    public function testRejectsRedirectUriThatDoesNotMatchTheBoundOne(): void
    {
        $this->storedAuthCode(isGeneric: true);
        $this->resolveRequestParams(redirectUri: 'https://attacker.example.org/callback');

        $this->assertRejects('invalid_grant', $this->request());
    }

    // Client authorization to use this grant at all.

    public function testRejectsClientNotRegisteredForTheAuthorizationCodeGrant(): void
    {
        $this->storedAuthCode(grantTypes: ['refresh_token']);

        $this->assertRejects('unauthorized_client', $this->request());
    }

    public function testAcceptsClientThatRegisteredNoGrantTypesAtAll(): void
    {
        // An empty list means nothing was registered, not "nothing is allowed" - manually managed and pre-DCR
        // clients have no grant_types, and gating on an empty list would lock every one of them out.
        $this->storedAuthCode(grantTypes: []);
        $this->expectAccessTokenToBeIssued();

        $this->sut()->respondToAccessTokenRequest($this->request(), $this->responseType(), new DateInterval('PT5M'));
    }

    public function testRejectsTokenRequestWithNeitherClientAuthenticationNorPkce(): void
    {
        // Nothing proves the caller is the client the code was issued to, so the code must not be redeemable.
        $this->storedAuthCode();
        $this->rulesReturn(codeVerifier: null, authenticationMethod: ClientAuthenticationMethodsEnum::None);

        $this->assertRejects('access_denied', $this->request());
    }

    // PKCE.

    public function testRejectsCodeVerifierWhenAuthorizationRequestHadNoCodeChallenge(): void
    {
        // PKCE downgrade: a verifier presented against a code that never carried a challenge must not be
        // treated as if PKCE had been performed.
        $this->storedAuthCode();
        $this->rulesReturn(codeVerifier: self::CODE_VERIFIER);

        $this->assertRejects('invalid_request', $this->request());
    }

    public function testRequiresCodeVerifierWhenAuthorizationRequestUsedCodeChallenge(): void
    {
        $this->storedAuthCode();
        $this->rulesReturn(codeVerifier: null);

        $this->assertRejects(
            'invalid_request',
            $this->requestFor($this->payloadWithChallenge()),
        );
    }

    public function testRejectsCodeVerifierThatFailsVerification(): void
    {
        $this->storedAuthCode();
        $this->rulesReturn(codeVerifier: 'a-completely-different-verifier');

        $this->assertRejects(
            'invalid_grant',
            $this->requestFor($this->payloadWithChallenge()),
        );
    }

    public function testAcceptsCodeVerifierThatVerifiesAgainstTheStoredChallenge(): void
    {
        $this->storedAuthCode();
        $this->rulesReturn(codeVerifier: self::CODE_VERIFIER);
        $this->expectAccessTokenToBeIssued();

        $this->sut()->respondToAccessTokenRequest(
            $this->requestFor($this->payloadWithChallenge(), ['code_verifier' => self::CODE_VERIFIER]),
            $this->responseType(),
            new DateInterval('PT5M'),
        );

        $this->assertSecretsWereNotLogged(self::CODE_VERIFIER);
    }

    public function testRejectsUnsupportedCodeChallengeMethod(): void
    {
        $this->storedAuthCode();
        $this->rulesReturn(codeVerifier: self::CODE_VERIFIER);

        $payload = $this->payloadWithChallenge();
        $payload['code_challenge_method'] = 'md5';

        $this->assertRejects('server_error', $this->requestFor($payload));
    }

    // Authorization code validation.

    public function testRejectsExpiredAuthorizationCode(): void
    {
        $this->storedAuthCode();

        $this->assertRejects(
            'invalid_grant',
            $this->requestFor($this->payload(['expire_time' => time() - 1])),
        );
    }

    public function testRevokesRelatedTokensWhenAuthorizationCodeIsReplayed(): void
    {
        // RFC 6749 section 4.1.2: a reused code means the code may be in an attacker's hands, so everything
        // already issued from it has to be revoked, not just this request refused.
        $this->storedAuthCode(isRevoked: true);

        $this->accessTokenRepositoryMock->expects($this->once())
            ->method('revokeByAuthCodeId')
            ->with(self::AUTH_CODE_ID);
        $this->refreshTokenRepositoryMock->expects($this->once())
            ->method('revokeByAuthCodeId')
            ->with(self::AUTH_CODE_ID);

        $this->assertRejects('invalid_grant', $this->request());
    }

    public function testRejectsAuthorizationCodeIssuedToAnotherClient(): void
    {
        $this->storedAuthCode();

        $this->assertRejects(
            'invalid_request',
            $this->requestFor($this->payload(['client_id' => 'another-client'])),
        );
    }

    public function testRequiresRedirectUriWhenTheAuthorizationRequestHadOne(): void
    {
        $this->storedAuthCode();

        // Body carrying the code but no redirect_uri, while the code was issued with one.
        $this->assertRejects(
            'invalid_request',
            $this->request(['code' => $this->encryptPayload($this->payload())]),
        );
    }

    public function testRejectsRedirectUriThatDiffersFromTheAuthorizationRequest(): void
    {
        $this->storedAuthCode();

        $this->assertRejects(
            'invalid_request',
            $this->request([
                'code' => $this->encryptPayload($this->payload()),
                'redirect_uri' => 'https://attacker.example.org/callback',
            ]),
        );
    }

    // Successful redemption.

    public function testIssuesAccessTokenAndRevokesTheAuthorizationCode(): void
    {
        $this->storedAuthCode();
        $accessToken = $this->expectAccessTokenToBeIssued();

        $responseType = $this->responseType();
        $responseType->expects($this->once())->method('setAccessToken')->with($accessToken);

        // The code has to be spent, otherwise it stays redeemable and replay detection never triggers.
        $this->authCodeRepositoryMock->expects($this->once())
            ->method('revokeAuthCode')
            ->with(self::AUTH_CODE_ID);

        $result = $this->sut()->respondToAccessTokenRequest(
            $this->request(),
            $responseType,
            new DateInterval('PT5M'),
        );

        $this->assertSame($responseType, $result);
    }

    public function testTakesTheClientFromTheStoredCodeRatherThanFromTheRequest(): void
    {
        // The client is authoritatively known from the stored code, so it is predefined as the ClientRule
        // result instead of being resolved again from request parameters. That is what lets client_id stay
        // optional here for authentication methods which convey the identity some other way.
        $authCode = $this->storedAuthCode();

        $this->requestRulesManagerMock->expects($this->once())
            ->method('predefineResult')
            ->with(
                $this->callback(
                    static fn(Result $result): bool => $result->getKey() === ClientRule::class &&
                        $result->getValue() === $authCode->getClient(),
                ),
            );

        $this->expectAccessTokenToBeIssued();

        $this->sut()->respondToAccessTokenRequest(
            $this->request(),
            $this->responseType(),
            new DateInterval('PT5M'),
        );
    }

    public function testRedeemsCodeForGenericClientBoundToItsClientIdAndRedirectUri(): void
    {
        // A generic (non-registered) client has no credential to authenticate with, so PKCE is what
        // authenticates it and the bound client_id and redirect_uri are what tie the code to it.
        $this->storedAuthCode(isGeneric: true);
        $this->rulesReturn(codeVerifier: self::CODE_VERIFIER);
        $accessToken = $this->expectAccessTokenToBeIssued();

        $responseType = $this->responseType();
        $responseType->expects($this->once())->method('setAccessToken')->with($accessToken);

        $this->sut()->respondToAccessTokenRequest(
            $this->requestFor($this->payloadWithChallenge()),
            $responseType,
            new DateInterval('PT5M'),
        );
    }

    public function testCarriesAuthenticationContextFromTheAuthorizationCodeIntoTheResponse(): void
    {
        $this->storedAuthCode();
        $this->expectAccessTokenToBeIssued();

        $responseType = $this->responseType();
        $responseType->expects($this->once())->method('setNonce')->with('the-nonce');
        $responseType->expects($this->once())->method('setAuthTime')->with(1_700_000_000);
        $responseType->expects($this->once())->method('setAcr')->with('urn:mace:incommon:iap:silver');
        $responseType->expects($this->once())->method('setSessionId')->with('the-session-id');

        $payload = $this->payload([
            'nonce' => 'the-nonce',
            'auth_time' => 1_700_000_000,
            'acr' => 'urn:mace:incommon:iap:silver',
            'session_id' => 'the-session-id',
        ]);

        $this->sut()->respondToAccessTokenRequest(
            $this->requestFor($payload),
            $responseType,
            new DateInterval('PT5M'),
        );
    }

    public function testIssuesRefreshTokenOnlyWhenOfflineAccessWasGranted(): void
    {
        $this->storedAuthCode();
        $accessToken = $this->expectAccessTokenToBeIssued();
        $refreshToken = $this->createMock(RefreshTokenEntityInterface::class);

        $this->offlineAccessGranted = true;

        $this->refreshTokenIssuerMock->expects($this->once())
            ->method('issue')
            ->with($accessToken, $this->anything(), self::AUTH_CODE_ID)
            ->willReturn($refreshToken);

        $responseType = $this->responseType();
        $responseType->expects($this->once())->method('setRefreshToken')->with($refreshToken);

        $this->sut()->respondToAccessTokenRequest($this->request(), $responseType, new DateInterval('PT5M'));
    }

    public function testDoesNotIssueRefreshTokenWithoutOfflineAccess(): void
    {
        $this->storedAuthCode();
        $this->expectAccessTokenToBeIssued();

        $this->refreshTokenIssuerMock->expects($this->never())->method('issue');

        $responseType = $this->responseType();
        $responseType->expects($this->never())->method('setRefreshToken');

        $this->sut()->respondToAccessTokenRequest($this->request(), $responseType, new DateInterval('PT5M'));
    }

    public function testDoesNotLogAnyCredentialFromTheTokenRequest(): void
    {
        // Every one of these is a credential: the code and the verifier redeem an authorization, the secret
        // authenticates the client. Logs are read far more widely than the token database, and the module's
        // logging policy is to record identifiers only. The grant opens by tracing the request, so this is
        // the test that keeps that trace from becoming a credential dump.
        $this->storedAuthCode();
        $this->rulesReturn(codeVerifier: self::CODE_VERIFIER);
        $this->expectAccessTokenToBeIssued();

        $clientSecret = 'client-secret-value';
        $encryptedAuthCode = $this->encryptPayload($this->payloadWithChallenge());

        $this->sut()->respondToAccessTokenRequest(
            $this->request([
                'code' => $encryptedAuthCode,
                'redirect_uri' => self::REDIRECT_URI,
                'code_verifier' => self::CODE_VERIFIER,
                'client_secret' => $clientSecret,
            ]),
            $this->responseType(),
            new DateInterval('PT5M'),
        );

        $this->assertSecretsWereNotLogged($encryptedAuthCode, self::CODE_VERIFIER, $clientSecret);

        // The parameter names are what makes a failed exchange diagnosable, so they must still be there.
        $this->assertStringContainsString('code_verifier', json_encode($this->logRecords, JSON_THROW_ON_ERROR));
    }

    // Helpers.

    private function sut(?OAuth2AuthCodeRepositoryInterface $authCodeRepository = null): AuthCodeGrant
    {
        $grant = new AuthCodeGrant(
            $authCodeRepository ?? $this->authCodeRepositoryMock,
            $this->accessTokenRepositoryMock,
            $this->refreshTokenRepositoryMock,
            new DateInterval('PT1M'),
            $this->requestRulesManagerMock,
            $this->requestParamsResolverMock,
            $this->accessTokenEntityFactoryMock,
            $this->authCodeEntityFactoryMock,
            $this->refreshTokenIssuerMock,
            $this->helpersMock,
            $this->loggerServiceMock,
        );

        $grant->setEncryptionKey($this->encryptionKey);
        $grant->setScopeRepository($this->scopeRepositoryMock);

        return $grant;
    }

    /**
     * Assert that redeeming the code fails with a given OAuth error type.
     *
     * The error type is what the client sees and what the specification pins down, so it is asserted instead
     * of the message. The grant raises the league exception in some branches and this module's subclass in
     * others; since the subclass extends the league one, catching that covers both, and which of the two is
     * thrown is an implementation detail the client cannot observe.
     */
    private function assertRejects(
        string $expectedErrorType,
        ServerRequestInterface $request,
        ?AuthCodeGrant $sut = null,
    ): void {
        try {
            ($sut ?? $this->sut())->respondToAccessTokenRequest(
                $request,
                $this->responseType(),
                new DateInterval('PT5M'),
            );
        } catch (OAuthServerException $exception) {
            $this->assertSame($expectedErrorType, $exception->getErrorType());

            return;
        }

        $this->fail(sprintf('Expected the token request to be rejected with "%s".', $expectedErrorType));
    }

    /**
     * @param array<string,mixed> $parsedBody
     */
    private function request(?array $parsedBody = null, bool $withRedirectUri = true): ServerRequestInterface
    {
        if ($parsedBody === null) {
            $parsedBody = ['code' => $this->encryptPayload($this->payload())];

            if ($withRedirectUri) {
                $parsedBody['redirect_uri'] = self::REDIRECT_URI;
            }
        }

        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getParsedBody')->willReturn($parsedBody);

        return $request;
    }

    /**
     * A complete token request for the given authorization code payload.
     *
     * The redirect_uri is included because this endpoint requires it whenever the authorization request had
     * one, and it is checked before PKCE. A request built without it is rejected for that reason first, which
     * would let a test aimed at some later check pass without ever reaching it.
     *
     * @param array<string,mixed> $payload
     * @param array<string,mixed> $extraBody Further parameters the client would send, such as credentials.
     */
    private function requestFor(array $payload, array $extraBody = []): ServerRequestInterface
    {
        return $this->request(array_merge(
            [
                'code' => $this->encryptPayload($payload),
                'redirect_uri' => self::REDIRECT_URI,
            ],
            $extraBody,
        ));
    }

    /**
     * The decrypted contents of an authorization code, as the authorization request half writes them.
     *
     * @param array<string,mixed> $overrides
     * @return array<string,mixed>
     */
    private function payload(array $overrides = []): array
    {
        return array_merge(
            [
                'auth_code_id' => self::AUTH_CODE_ID,
                'client_id' => self::CLIENT_ID,
                'user_id' => self::USER_ID,
                'scopes' => ['openid'],
                'redirect_uri' => self::REDIRECT_URI,
                'expire_time' => time() + 300,
            ],
            $overrides,
        );
    }

    /**
     * @return array<string,mixed>
     */
    private function payloadWithChallenge(string $method = 'S256'): array
    {
        // The base64url encoded SHA-256 of the verifier, as RFC 7636 section 4.2 defines it. Computed here
        // rather than taken from the verifier class, so that a change in the library cannot quietly move both
        // sides of the comparison at once.
        $challenge = strtr(rtrim(base64_encode(hash('sha256', self::CODE_VERIFIER, true)), '='), '+/', '-_');

        return $this->payload([
            'code_challenge' => $challenge,
            'code_challenge_method' => $method,
        ]);
    }

    /**
     * @param array<string,mixed> $payload
     */
    private function encryptPayload(array $payload, ?Key $key = null): string
    {
        // encrypt() is protected on the grant, and reproducing it here would test the test rather than the
        // format the grant actually reads, so it is called on a grant instance bound to the given key.
        $grant = $this->sut();
        $grant->setEncryptionKey($key ?? $this->encryptionKey);

        $encrypt = Closure::bind(
            fn(string $data): string => $this->encrypt($data),
            $grant,
            AuthCodeGrant::class,
        );

        return $encrypt(json_encode($payload, JSON_THROW_ON_ERROR));
    }

    /**
     * Put an authorization code in storage and make the rules answer for the client it was issued to.
     *
     * @param string[]|null $grantTypes
     */
    private function storedAuthCode(
        bool $isGeneric = false,
        bool $isRevoked = false,
        ?array $grantTypes = null,
    ): AuthCodeEntity {
        $client = $this->createMock(ClientEntity::class);
        $client->method('getIdentifier')->willReturn(self::CLIENT_ID);
        $client->method('isGeneric')->willReturn($isGeneric);
        $client->method('getGrantTypes')->willReturn($grantTypes ?? ['authorization_code']);

        $authCode = new AuthCodeEntity(
            self::AUTH_CODE_ID,
            $client,
            [],
            new DateTimeImmutable('+1 hour'),
            self::USER_ID,
            self::REDIRECT_URI,
            isRevoked: $isRevoked,
            boundClientId: self::CLIENT_ID,
            boundRedirectUri: self::REDIRECT_URI,
        );

        $this->authCodeRepositoryMock->method('findById')->willReturn($authCode);

        if ($isGeneric) {
            $this->resolveRequestParams();
        }

        $this->rulesReturn();

        return $authCode;
    }

    /**
     * What the generic-client branch reads straight off the request rather than through the rules.
     */
    private function resolveRequestParams(
        ?string $clientId = self::CLIENT_ID,
        ?string $redirectUri = self::REDIRECT_URI,
    ): void {
        $this->requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $this->resolverReturnsTheRequestBody($this->requestParamsResolverMock);
        $this->requestParamsResolverMock->method('getAsStringBasedOnAllowedMethods')
            ->willReturnCallback(
                static fn(string $parameter): ?string => match ($parameter) {
                    ParamsEnum::ClientId->value => $clientId,
                    ParamsEnum::RedirectUri->value => $redirectUri,
                    default => null,
                },
            );
    }

    /**
     * Make the resolver hand back the request body, the way the real one does.
     *
     * A resolver stubbed to return an empty array would silently strip the credentials out of everything
     * the grant logs, which makes the secrecy assertions below pass no matter what the grant does with
     * them. That is exactly how the debug dump of the whole token request body went unnoticed.
     */
    private function resolverReturnsTheRequestBody(RequestParamsResolver&MockObject $resolver): void
    {
        $resolver->method('getAllBasedOnAllowedMethods')
            ->willReturnCallback(
                static fn(ServerRequestInterface $request): array => (array)$request->getParsedBody(),
            );
    }

    private function rulesReturn(
        ?string $codeVerifier = null,
        ClientAuthenticationMethodsEnum $authenticationMethod = ClientAuthenticationMethodsEnum::ClientSecretBasic,
    ): void {
        $resultBag = new ResultBag();
        $resultBag->add(new Result(CodeVerifierRule::class, $codeVerifier));
        $resultBag->add(
            new Result(
                ClientAuthenticationRule::class,
                new ResolvedClientAuthenticationMethod(
                    $this->createMock(ClientEntity::class),
                    $authenticationMethod,
                ),
            ),
        );

        $this->requestRulesManagerMock = $this->createMock(RequestRulesManager::class);
        $this->requestRulesManagerMock->method('check')->willReturn($resultBag);
    }

    private function expectAccessTokenToBeIssued(): AccessTokenEntity&MockObject
    {
        $accessToken = $this->createMock(AccessTokenEntity::class);

        $this->accessTokenEntityFactoryMock->method('fromData')->willReturn($accessToken);
        $this->accessTokenRepositoryMock->expects($this->once())
            ->method('persistNewAccessToken')
            ->with($accessToken);

        return $accessToken;
    }

    /**
     * @return ResponseTypeInterface&MockObject
     */
    private function responseType(): MockObject
    {
        return $this->createMockForIntersectionOfInterfaces([
            ResponseTypeInterface::class,
            NonceResponseTypeInterface::class,
            AuthTimeResponseTypeInterface::class,
            AcrResponseTypeInterface::class,
            SessionIdResponseTypeInterface::class,
        ]);
    }

    private function captureLogs(string $level): void
    {
        $this->loggerServiceMock->method($level)->willReturnCallback(
            function (string|Stringable $message, array $context = []): void {
                $this->logRecords[] = ['message' => (string)$message, 'context' => $context];
            },
        );
    }

    private function assertSecretsWereNotLogged(string ...$secrets): void
    {
        $logs = json_encode($this->logRecords, JSON_THROW_ON_ERROR);

        foreach ($secrets as $secret) {
            $this->assertStringNotContainsString($secret, $logs);
        }
    }
}
