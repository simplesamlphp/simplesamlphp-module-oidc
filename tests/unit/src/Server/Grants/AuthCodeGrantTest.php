<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\Grants;

use ArrayObject;
use Closure;
use DateInterval;
use DateTimeImmutable;
use Defuse\Crypto\Key;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface as OAuth2AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest as OAuth2AuthorizationRequest;
use League\OAuth2\Server\ResponseTypes\AbstractResponseType;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use LogicException;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;
use SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\AuthCodeEntity;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\RefreshTokenEntityInterface;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Factories\Entities\AccessTokenEntityFactory;
use SimpleSAML\Module\oidc\Factories\Entities\AuthCodeEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Helpers\Arr;
use SimpleSAML\Module\oidc\Helpers\Scope;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AuthCodeRepository;
use SimpleSAML\Module\oidc\Repositories\Interfaces\AccessTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Repositories\Interfaces\RefreshTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Repositories\IssuerStateRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\Grants\AuthCodeGrant;
use SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\AcrValuesRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\AuthorizationDetailsRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientAuthenticationRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientIdRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\CodeChallengeMethodRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\CodeChallengeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\CodeVerifierRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\DpopJktRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\IdTokenHintRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\IssuerStateRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\LoginHintRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\MaxAgeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\OfferedCredentialsRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\PromptRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequestedClaimsRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ResponseModeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ScopeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\UiLocalesRule;
use SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Server\ResponseTypes\Interfaces\AcrResponseTypeInterface;
use SimpleSAML\Module\oidc\Server\ResponseTypes\Interfaces\AuthTimeResponseTypeInterface;
use SimpleSAML\Module\oidc\Server\ResponseTypes\Interfaces\NonceResponseTypeInterface;
use SimpleSAML\Module\oidc\Server\ResponseTypes\Interfaces\SessionIdResponseTypeInterface;
use SimpleSAML\Module\oidc\Server\TokenIssuers\RefreshTokenIssuer;
use SimpleSAML\Module\oidc\Server\Validators\DpopProofVerifier;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\AccessTokenClaimsResolver;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Module\oidc\Utils\SubjectResolver;
use SimpleSAML\Module\oidc\ValueAbstracts\ResolvedClientAuthenticationMethod;
use SimpleSAML\Module\oidc\ValueAbstracts\VerifiedDpopProof;
use SimpleSAML\OpenID\Codebooks\ClientAuthenticationMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;
use SimpleSAML\OpenID\Core\IdTokenHint;
use SimpleSAML\OpenID\OAuth2\DpopProof;
use Stringable;
use Throwable;

/**
 * The authorization code grant, at both of the endpoints it takes part in.
 *
 * Covers both halves of the grant: the code redemption reachable from respondToAccessTokenRequest(),
 * including validateAuthorizationCode(), and the authorization request half
 * (validateAuthorizationRequestWithRequestRules(), completeOidcAuthorizationRequest()).
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
#[UsesClass(AuthorizationRequest::class)]
#[UsesClass(UserEntity::class)]
#[UsesClass(Arr::class)]
#[UsesClass(QueryResponseMode::class)]
#[AllowMockObjectsWithoutExpectations]
class AuthCodeGrantTest extends TestCase
{
    private const string AUTH_CODE_ID = 'auth-code-id';

    private const string CLIENT_ID = 'client-id';

    private const string USER_ID = 'user-id';

    private const string REDIRECT_URI = 'https://rp.example.org/callback';

    private const string STATE = 'opaque-state-value';

    private const string ISSUER = 'https://op.example.org';

    private const string CODE_VERIFIER = 'ZG9uLXQtdXNlLXRoaXMtdmVyaWZpZXItaW4tcHJvZHVjdGlvbg';

    private const string ISSUER_STATE = 'issuer-state-of-a-credential-offer';


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

    private UserRepository&MockObject $userRepositoryMock;

    private SubjectResolver&MockObject $subjectResolverMock;

    private AccessTokenClaimsResolver&MockObject $accessTokenClaimsResolverMock;

    private ScopeRepositoryInterface&MockObject $scopeRepositoryMock;

    private ModuleConfig&MockObject $moduleConfigMock;

    private IssuerStateRepository&MockObject $issuerStateRepositoryMock;

    private Key $encryptionKey;

    /** Whether the granted scopes are treated as containing offline_access. */
    private bool $offlineAccessGranted = false;

    /** What ModuleConfig answers for the lifetime of an access token for credential issuance. */
    private string $vciAccessTokenTtl = 'PT5M';

    /** What ModuleConfig answers for vci_require_dpop. */
    private bool $vciRequireDpop = false;

    /** @var string[] Scope identifiers the scope repository no longer resolves, as ModuleConfig::getScopes() drops them. */
    private array $unsupportedScopes = [];

    /** @var array<int,array{level:string,message:string,context:array}> */
    private array $logRecords = [];

    /** What the access token factory was last called with, for assertions on values with no other outlet. */
    private array $accessTokenFactoryArguments = [];

    /** @var string[] The rules the grant last asked the rules manager to check, in order. */
    private array $checkedRules = [];

    /** Whether the code is still there to consume, or another request consumed it first. */
    private bool $authCodeIsConsumable = true;


    protected function setUp(): void
    {
        $this->authCodeRepositoryMock = $this->createMock(AuthCodeRepository::class);
        $this->authCodeRepositoryMock->method('consumeAuthCode')
            ->willReturnCallback(fn(): bool => $this->authCodeIsConsumable);
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
        $this->userRepositoryMock = $this->createMock(UserRepository::class);
        $this->subjectResolverMock = $this->createMock(SubjectResolver::class);
        $this->accessTokenClaimsResolverMock = $this->createMock(AccessTokenClaimsResolver::class);
        $this->scopeRepositoryMock = $this->createMock(ScopeRepositoryInterface::class);
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getIssuer')->willReturn(self::ISSUER);
        $this->moduleConfigMock->method('getVciAccessTokenDuration')
            ->willReturnCallback(fn(): DateInterval => new DateInterval($this->vciAccessTokenTtl));
        $this->moduleConfigMock->method('getVciRequireDpop')->willReturnCallback(fn(): bool => $this->vciRequireDpop);
        $this->issuerStateRepositoryMock = $this->createMock(IssuerStateRepository::class);

        // A Key rather than a password string: both are accepted by the grant, but the password form runs a
        // key derivation on every encrypt and decrypt, which this many round trips would make noticeably slow.
        $this->encryptionKey = Key::createNewRandomKey();

        $this->helpersMock->method('scope')->willReturn($this->scopeHelperMock);
        // The real array helper rather than a double: findByCallback() is a pure function, and stubbing it
        // would mean deciding in the test what counts as an OIDC request, which is the thing under test.
        $this->helpersMock->method('arr')->willReturn(new Arr());
        $this->scopeHelperMock->method('exists')->willReturnCallback(fn(): bool => $this->offlineAccessGranted);

        $this->scopeRepositoryMock->method('getScopeEntityByIdentifier')
            ->willReturnCallback(fn(string $identifier): ?ScopeEntity => in_array(
                $identifier,
                $this->unsupportedScopes,
                true,
            ) ? null : new ScopeEntity($identifier));
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

    // Credential Offer redemption.

    /**
     * The code of a request which followed a Credential Offer carries the offer's issuer state, and redeeming
     * the code spends it. The token carries the state on, which is how the credential endpoint knows the token
     * followed an offer.
     */
    public function testSpendsTheIssuerStateOfACredentialOfferCodeAndCarriesItOntoTheToken(): void
    {
        $this->storedAuthCode(issuerState: self::ISSUER_STATE, flowType: FlowTypeEnum::VciAuthorizationCode);
        $this->expectAccessTokenToBeIssued();
        $this->issuerStateRepositoryMock->expects($this->once())
            ->method('consume')
            ->with(self::ISSUER_STATE)
            ->willReturn(true);
        $this->issuerStateRepositoryMock->expects($this->never())->method('release');

        $this->sut()->respondToAccessTokenRequest($this->request(), $this->responseType(), new DateInterval('PT5M'));

        // The double receives the factory's arguments by position, and the issuer state is the thirteenth.
        $this->assertSame(self::ISSUER_STATE, $this->accessTokenFactoryArguments[12]);
    }


    /**
     * An offer is redeemed once. A second code obtained with it, by the same wallet or another, gets no token,
     * and neither does a code whose offer expired before it was redeemed. The code is spent, and then only its own
     * tokens are revoked: those of a code which did redeem the offer are not this code's, and a refusal which
     * revoked them would let whoever holds a copy of an offer cut off the wallet it was meant for. This code's own
     * are there when the offer was redeemed with this very code, by a request presenting it at the same time which
     * consumed it first, having stored its tokens before. Spent before the revocation, so that such a request
     * which has not consumed the code yet can no longer do so once this one revoked what it found.
     */
    public function testRefusesACodeWhoseCredentialOfferCanNoLongerBeRedeemed(): void
    {
        $this->storedAuthCode(issuerState: self::ISSUER_STATE, flowType: FlowTypeEnum::VciAuthorizationCode);
        $this->issuerStateRepositoryMock->method('consume')->willReturn(false);
        $this->accessTokenRepositoryMock->expects($this->never())->method('persistNewAccessToken');
        $calls = $this->recordRecoveryCalls();
        $this->recordConsumedAuthCodes($calls);

        $this->assertRejects('invalid_grant', $this->request());

        $this->assertSame(
            [
                ['consume', self::AUTH_CODE_ID],
                ['access', self::AUTH_CODE_ID],
                ['refresh', self::AUTH_CODE_ID],
            ],
            $calls->getArrayCopy(),
        );
    }


    /**
     * The other side of that race: a request which redeemed the offer with a code, while one presenting the same
     * code at the same time was refused at the offer and consumed the code first, is refused when it consumes the
     * code. What it issued is revoked, as for a replay and again by the recovery, and the offer given back, so that
     * no token from the offer outlives the replay and the wallet can start over from the offer.
     */
    public function testGivesTheOfferBackWhenARequestRefusedAtTheOfferConsumedTheCodeFirst(): void
    {
        $this->storedAuthCode(issuerState: self::ISSUER_STATE, flowType: FlowTypeEnum::VciAuthorizationCode);
        $this->issuerStateRepositoryMock->method('consume')->willReturn(true);
        $this->authCodeIsConsumable = false;
        $this->expectAccessTokenToBeIssued();
        $calls = $this->recordRecoveryCalls();
        $this->recordConsumedAuthCodes($calls);

        $this->assertRejects('invalid_grant', $this->request());

        $this->assertSame(
            [
                ['consume', self::AUTH_CODE_ID],
                ['access', self::AUTH_CODE_ID],
                ['refresh', self::AUTH_CODE_ID],
                ['access', self::AUTH_CODE_ID],
                ['refresh', self::AUTH_CODE_ID],
                ['release', self::ISSUER_STATE],
            ],
            $calls->getArrayCopy(),
        );
    }


    /**
     * The offer is spent before the tokens are issued. Should the issuance fail, what was issued for the code
     * is revoked and then the offer given back, so the wallet can retry the code it still holds instead of
     * holding an offer used up for no token, and the failure goes on to the client as it was. Revoked first,
     * so that a failure to revoke leaves the offer spent rather than two sets of tokens from it.
     */
    public function testGivesTheOfferBackWhenTheTokenCanNotBeIssued(): void
    {
        $this->storedAuthCode(issuerState: self::ISSUER_STATE, flowType: FlowTypeEnum::VciAuthorizationCode);
        $this->issuerStateRepositoryMock->method('consume')->willReturn(true);
        $failure = new RuntimeException('The access token could not be built.');
        $this->accessTokenEntityFactoryMock->method('fromData')->willThrowException($failure);
        $calls = $this->recordRecoveryCalls();

        try {
            $this->sut()->respondToAccessTokenRequest(
                $this->request(),
                $this->responseType(),
                new DateInterval('PT5M'),
            );
            $this->fail('The failure to issue the token must reach the caller.');
        } catch (RuntimeException $exception) {
            $this->assertSame($failure, $exception);
        }

        $this->assertSame(
            [
                ['access', self::AUTH_CODE_ID],
                ['refresh', self::AUTH_CODE_ID],
                ['release', self::ISSUER_STATE],
            ],
            $calls->getArrayCopy(),
        );
    }


    /**
     * A refresh token is issued after the access token, so a failure there comes once an access token was
     * persisted. The offer is given back all the same, and the access token, which never reached the wallet,
     * is revoked with it.
     */
    public function testGivesTheOfferBackWhenTheRefreshTokenCanNotBeIssued(): void
    {
        $this->storedAuthCode(issuerState: self::ISSUER_STATE, flowType: FlowTypeEnum::VciAuthorizationCode);
        $this->issuerStateRepositoryMock->method('consume')->willReturn(true);
        $this->expectAccessTokenToBeIssued();
        $this->offlineAccessGranted = true;
        $failure = new RuntimeException('The refresh token could not be persisted.');
        $this->refreshTokenIssuerMock->method('issue')->willThrowException($failure);
        $calls = $this->recordRecoveryCalls();

        try {
            $this->sut()->respondToAccessTokenRequest(
                $this->request(),
                $this->responseType(),
                new DateInterval('PT5M'),
            );
            $this->fail('The failure to issue the refresh token must reach the caller.');
        } catch (RuntimeException $exception) {
            $this->assertSame($failure, $exception);
        }

        $this->assertSame(
            [
                ['access', self::AUTH_CODE_ID],
                ['refresh', self::AUTH_CODE_ID],
                ['release', self::ISSUER_STATE],
            ],
            $calls->getArrayCopy(),
        );
    }


    /**
     * The offer is given back only once what was issued for the code is revoked. Should the revocation fail,
     * the offer stays spent: given back with the tokens still live, a retry of the code would take a second
     * set of tokens from one offer. The failure to revoke is logged rather than thrown, so the caller still gets
     * the failure recovered from, which is the one the client is answered for.
     */
    public function testKeepsTheOfferSpentWhenWhatWasIssuedCanNotBeRevoked(): void
    {
        $this->storedAuthCode(issuerState: self::ISSUER_STATE, flowType: FlowTypeEnum::VciAuthorizationCode);
        $this->issuerStateRepositoryMock->method('consume')->willReturn(true);
        $failure = new RuntimeException('The access token could not be built.');
        $this->accessTokenEntityFactoryMock->method('fromData')->willThrowException($failure);
        $this->accessTokenRepositoryMock->method('revokeByAuthCodeId')
            ->willThrowException(new LogicException('The tokens could not be revoked.'));
        $this->refreshTokenRepositoryMock->expects($this->never())->method('revokeByAuthCodeId');
        $this->issuerStateRepositoryMock->expects($this->never())->method('release');

        $this->assertTheCallerGets($failure);

        $this->assertRecoveryFailureWasLogged(
            RuntimeException::class . ': The access token could not be built.',
            LogicException::class . ': The tokens could not be revoked.',
        );
    }


    /**
     * The refresh tokens are revoked after the access tokens, and the offer is given back only once both are.
     * Should only the refresh tokens fail to be revoked, the offer stays spent all the same: a refresh token left
     * live would let a retry of the code take a second set of tokens from one offer.
     */
    public function testKeepsTheOfferSpentWhenTheRefreshTokensCanNotBeRevoked(): void
    {
        $this->storedAuthCode(issuerState: self::ISSUER_STATE, flowType: FlowTypeEnum::VciAuthorizationCode);
        $this->issuerStateRepositoryMock->method('consume')->willReturn(true);
        $failure = new RuntimeException('The access token could not be built.');
        $this->accessTokenEntityFactoryMock->method('fromData')->willThrowException($failure);
        $this->accessTokenRepositoryMock->expects($this->once())->method('revokeByAuthCodeId')
            ->with(self::AUTH_CODE_ID);
        $this->refreshTokenRepositoryMock->expects($this->once())->method('revokeByAuthCodeId')
            ->with(self::AUTH_CODE_ID)
            ->willThrowException(new LogicException('The refresh tokens could not be revoked.'));
        $this->issuerStateRepositoryMock->expects($this->never())->method('release');

        $this->assertTheCallerGets($failure);

        $this->assertRecoveryFailureWasLogged(
            RuntimeException::class . ': The access token could not be built.',
            LogicException::class . ': The refresh tokens could not be revoked.',
        );
    }


    /**
     * Should giving the offer back fail once what was issued for the code is revoked, the offer may stay
     * spent, and the wallet needs a new one; the caller still gets the failure recovered from.
     */
    public function testKeepsTheFailureRecoveredFromWhenTheOfferCanNotBeGivenBack(): void
    {
        $this->storedAuthCode(issuerState: self::ISSUER_STATE, flowType: FlowTypeEnum::VciAuthorizationCode);
        $this->issuerStateRepositoryMock->method('consume')->willReturn(true);
        $failure = new RuntimeException('The access token could not be built.');
        $this->accessTokenEntityFactoryMock->method('fromData')->willThrowException($failure);
        $this->accessTokenRepositoryMock->expects($this->once())->method('revokeByAuthCodeId')
            ->with(self::AUTH_CODE_ID);
        $this->refreshTokenRepositoryMock->expects($this->once())->method('revokeByAuthCodeId')
            ->with(self::AUTH_CODE_ID);
        $this->issuerStateRepositoryMock->expects($this->once())->method('release')->with(self::ISSUER_STATE)
            ->willThrowException(new LogicException('The offer could not be given back.'));

        $this->assertTheCallerGets($failure);

        $this->assertRecoveryFailureWasLogged(
            RuntimeException::class . ': The access token could not be built.',
            LogicException::class . ': The offer could not be given back.',
        );
    }


    /**
     * Without an offer there is nothing to give back when the token can not be issued.
     */
    public function testGivesNothingBackForACodeWhichFollowedNoOfferWhenTheTokenCanNotBeIssued(): void
    {
        $this->storedAuthCode(flowType: FlowTypeEnum::VciAuthorizationCode);
        $failure = new RuntimeException('The access token could not be built.');
        $this->accessTokenEntityFactoryMock->method('fromData')->willThrowException($failure);
        $this->issuerStateRepositoryMock->expects($this->never())->method('release');
        $this->accessTokenRepositoryMock->expects($this->never())->method('revokeByAuthCodeId');
        $this->refreshTokenRepositoryMock->expects($this->never())->method('revokeByAuthCodeId');

        try {
            $this->sut()->respondToAccessTokenRequest(
                $this->request(),
                $this->responseType(),
                new DateInterval('PT5M'),
            );
            $this->fail('The failure to issue the token must reach the caller.');
        } catch (RuntimeException $exception) {
            $this->assertSame($failure, $exception);
        }
    }


    /**
     * A request which fails another check does not use the offer up: the issuer state is spent only once every
     * other check has passed, so the wallet can still redeem the offer with a request which passes them.
     */
    public function testDoesNotSpendTheIssuerStateOfACodeWhoseRequestFailsAnotherCheck(): void
    {
        $this->storedAuthCode(issuerState: self::ISSUER_STATE, flowType: FlowTypeEnum::VciAuthorizationCode);
        $this->rulesReturn(codeVerifier: 'a-completely-different-verifier');
        $this->issuerStateRepositoryMock->expects($this->never())->method('consume');

        $this->assertRejects('invalid_grant', $this->requestFor($this->payloadWithChallenge()));
    }


    /**
     * A wallet which started the flow on its own followed no offer, so its code has no issuer state to spend.
     */
    public function testSpendsNoIssuerStateForACodeWhichFollowedNoOffer(): void
    {
        $this->storedAuthCode(flowType: FlowTypeEnum::VciAuthorizationCode);
        $this->expectAccessTokenToBeIssued();
        $this->issuerStateRepositoryMock->expects($this->never())->method('consume');

        $this->sut()->respondToAccessTokenRequest($this->request(), $this->responseType(), new DateInterval('PT5M'));
    }


    /**
     * Only an OpenID4VCI code follows an offer. An issuer state on a code of another flow names no offer this
     * server issued the code against, and is not spent.
     */
    public function testSpendsNoIssuerStateForACodeOfAnotherFlow(): void
    {
        $this->storedAuthCode(issuerState: self::ISSUER_STATE, flowType: FlowTypeEnum::OidcAuthorizationCode);
        $this->expectAccessTokenToBeIssued();
        $this->issuerStateRepositoryMock->expects($this->never())->method('consume');

        $this->sut()->respondToAccessTokenRequest($this->request(), $this->responseType(), new DateInterval('PT5M'));
    }

    // Successful redemption.

    public function testIssuesAccessTokenAndConsumesTheAuthorizationCode(): void
    {
        $this->storedAuthCode();
        $accessToken = $this->expectAccessTokenToBeIssued();

        $responseType = $this->responseType();
        $responseType->expects($this->once())->method('setAccessToken')->with($accessToken);

        // The code has to be spent, otherwise it stays redeemable and replay detection never triggers.
        $this->authCodeRepositoryMock->expects($this->once())
            ->method('consumeAuthCode')
            ->with(self::AUTH_CODE_ID);
        $this->accessTokenRepositoryMock->expects($this->never())->method('revokeByAuthCodeId');
        $this->refreshTokenRepositoryMock->expects($this->never())->method('revokeByAuthCodeId');

        $result = $this->sut()->respondToAccessTokenRequest(
            $this->request(),
            $responseType,
            new DateInterval('PT5M'),
        );

        $this->assertSame($responseType, $result);
    }


    /**
     * Of several requests presenting the same code at once, each finds it unrevoked when it looks it up, and only
     * the one which consumes it first is answered with tokens. Any other is refused as a replay, and revokes
     * everything issued for the code, those tokens included, per RFC 6749 section 4.1.2. The code is consumed only
     * once the tokens are stored: the request which got through stored its tokens before it consumed the code, so
     * they are there to revoke.
     */
    public function testRefusesACodeAnotherRequestConsumedFirstAndRevokesWhatWasIssuedForIt(): void
    {
        $this->storedAuthCode();
        $this->authCodeIsConsumable = false;
        $this->expectAccessTokenToBeIssued();
        $this->offlineAccessGranted = true;
        $calls = $this->recordRecoveryCalls();
        $this->accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnCallback(
            function () use ($calls): void {
                $calls->append(['persist access token']);
            },
        );
        $this->refreshTokenIssuerMock->method('issue')->willReturnCallback(
            function () use ($calls): RefreshTokenEntityInterface {
                $calls->append(['issue refresh token']);

                return $this->createStub(RefreshTokenEntityInterface::class);
            },
        );
        $this->recordConsumedAuthCodes($calls);

        $this->assertRejects('invalid_grant', $this->request());

        $this->assertSame(
            [
                ['persist access token'],
                ['issue refresh token'],
                ['consume', self::AUTH_CODE_ID],
                ['access', self::AUTH_CODE_ID],
                ['refresh', self::AUTH_CODE_ID],
            ],
            $calls->getArrayCopy(),
        );
    }


    /**
     * The code is consumed last. A request whose issuance fails leaves it unconsumed, which is what lets the
     * wallet retry it once the offer it followed is given back.
     */
    public function testLeavesTheCodeUnconsumedWhenTheRefreshTokenCanNotBeIssued(): void
    {
        $this->storedAuthCode(issuerState: self::ISSUER_STATE, flowType: FlowTypeEnum::VciAuthorizationCode);
        $this->issuerStateRepositoryMock->method('consume')->willReturn(true);
        $this->expectAccessTokenToBeIssued();
        $this->offlineAccessGranted = true;
        $this->refreshTokenIssuerMock->method('issue')
            ->willThrowException(new RuntimeException('The refresh token could not be persisted.'));
        $this->authCodeRepositoryMock->expects($this->never())->method('consumeAuthCode');

        $this->expectException(RuntimeException::class);

        $this->sut()->respondToAccessTokenRequest($this->request(), $this->responseType(), new DateInterval('PT5M'));
    }


    /**
     * The token endpoint holds only the user id from the code, so the mint looks the record up and resolves the
     * subject and the access token claims from it; both reach the factory by name.
     */
    public function testMintsTheAccessTokenWithTheResolvedSubjectAndClaims(): void
    {
        $this->storedAuthCode();
        $this->expectAccessTokenToBeIssued();

        $user = $this->createMock(UserEntity::class);
        $this->userRepositoryMock->expects($this->once())
            ->method('getUserEntityByIdentifier')
            ->with(self::USER_ID)
            ->willReturn($user);
        $this->subjectResolverMock->expects($this->once())
            ->method('resolve')
            ->with($user)
            ->willReturn('resolved-subject');
        $this->accessTokenClaimsResolverMock->expects($this->once())
            ->method('resolve')
            ->with(
                $user,
                $this->callback(fn(array $scopes): bool => array_map(
                    fn(ScopeEntity $scope): string => $scope->getIdentifier(),
                    array_values($scopes),
                ) === ['openid']),
            )
            ->willReturn(['voperson_id' => 'v1@example.org']);

        $this->sut()->respondToAccessTokenRequest($this->request(), $this->responseType(), new DateInterval('PT5M'));

        // fromData() is called with a mix of positional and named arguments; a mock sees them all by position.
        $this->assertSame(self::USER_ID, $this->accessTokenFactoryArguments[4]);
        $this->assertSame('resolved-subject', $this->accessTokenFactoryArguments[13]);
        $this->assertSame(['voperson_id' => 'v1@example.org'], $this->accessTokenFactoryArguments[14]);
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


    /**
     * Why the grant carries no refresh token guard of its own: with the refresh token grant disabled,
     * ModuleConfig::getScopes() leaves `offline_access` out, the scope repository no longer resolves it, and
     * validateScopes() refuses the code before the refresh token branch is reached. Pinned against an
     * authorization code issued with the scope just before the option changed.
     */
    public function testRejectsAnAuthorizationCodeCarryingAScopeTheRepositoryNoLongerKnows(): void
    {
        $this->storedAuthCode();
        $this->unsupportedScopes = ['offline_access'];
        $this->offlineAccessGranted = true;

        $this->refreshTokenIssuerMock->expects($this->never())->method('issue');

        $this->assertRejects(
            'invalid_scope',
            $this->requestFor($this->payload(['scopes' => ['openid', 'offline_access']])),
        );
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

    // Authorization request: deciding whether this grant handles it at all.

    public function testRespondsOnlyToAuthorizationRequestsAskingForACode(): void
    {
        $sut = $this->sut();

        $this->assertTrue(
            $sut->canRespondToAuthorizationRequest(
                $this->request(['response_type' => 'code', 'client_id' => self::CLIENT_ID]),
            ),
        );
        $this->assertFalse(
            $sut->canRespondToAuthorizationRequest(
                $this->request(['response_type' => 'token', 'client_id' => self::CLIENT_ID]),
            ),
            'A request for an implicit response type belongs to a different grant.',
        );
        $this->assertFalse(
            $sut->canRespondToAuthorizationRequest($this->request(['response_type' => 'code'])),
            'Without a client_id there is nothing to resolve the request against.',
        );
        $this->assertFalse($sut->canRespondToAuthorizationRequest($this->request([])));
    }


    public function testTreatsARequestAsOidcOnlyWhenItAsksForTheOpenidScope(): void
    {
        $sut = $this->sut();

        $this->assertTrue($sut->isOidcCandidate($this->oAuth2AuthorizationRequest([new ScopeEntity('openid')])));
        $this->assertFalse($sut->isOidcCandidate($this->oAuth2AuthorizationRequest([new ScopeEntity('profile')])));
        $this->assertFalse($sut->isOidcCandidate($this->oAuth2AuthorizationRequest([])));
    }

    // Authorization request validation.

    public function testReturnsAPlainOAuth2RequestWhenItIsNeitherOidcNorVerifiableCredential(): void
    {
        // No openid scope and not a credential request, so there is nothing OIDC-specific to carry and the
        // grant must not promote it to the richer request type.
        $request = $this->validatedAuthorizationRequest(scopes: [new ScopeEntity('profile')]);

        $this->assertInstanceOf(OAuth2AuthorizationRequest::class, $request);
        $this->assertNotInstanceOf(AuthorizationRequest::class, $request);
    }


    public function testReturnsAnOidcRequestWhenTheOpenidScopeIsRequested(): void
    {
        $this->assertInstanceOf(AuthorizationRequest::class, $this->validatedAuthorizationRequest());
    }


    public function testReturnsAnOidcRequestForACredentialRequestWithoutTheOpenidScope(): void
    {
        // A wallet asking for a credential does not send openid, but still needs the OIDC request type.
        $request = $this->validatedAuthorizationRequest(
            scopes: [new ScopeEntity('profile')],
            isVciRequest: true,
        );

        $this->assertInstanceOf(AuthorizationRequest::class, $request);
        $this->assertTrue($request->isVciRequest());
        $this->assertSame(FlowTypeEnum::VciAuthorizationCode, $request->getFlowType());
    }


    public function testCarriesTheCodeChallengeOntoTheAuthorizationRequestOnlyWhenOneWasSent(): void
    {
        $withPkce = $this->validatedAuthorizationRequest(
            ruleResults: [CodeChallengeRule::class => $this->codeChallenge(), CodeChallengeMethodRule::class => 'S256'],
        );

        $this->assertSame($this->codeChallenge(), $withPkce->getCodeChallenge());
        $this->assertSame('S256', $withPkce->getCodeChallengeMethod());

        $this->setUp();

        $this->assertNull($this->validatedAuthorizationRequest()->getCodeChallenge());
    }


    public function testCarriesTheAuthenticationContextParametersOntoTheAuthorizationRequest(): void
    {
        $idTokenHint = $this->createMock(IdTokenHint::class);
        $idTokenHint->method('getSubject')->willReturn('the-subject');

        $request = $this->validatedAuthorizationRequest(
            nonce: 'the-nonce',
            ruleResults: [
                MaxAgeRule::class => 1_700_000_000,
                RequestedClaimsRule::class => ['userinfo' => ['email' => null]],
                AcrValuesRule::class => ['urn:mace:incommon:iap:silver'],
                UiLocalesRule::class => 'hr en',
                LoginHintRule::class => 'user@example.org',
                IdTokenHintRule::class => $idTokenHint,
                IssuerStateRule::class => 'issuer-state-value',
            ],
        );

        $this->assertSame('the-nonce', $request->getNonce());
        $this->assertSame(1_700_000_000, $request->getAuthTime());
        $this->assertSame(['userinfo' => ['email' => null]], $request->getClaims());
        $this->assertSame(['urn:mace:incommon:iap:silver'], $request->getRequestedAcrValues());
        $this->assertSame('hr en', $request->getUiLocales());
        $this->assertSame('user@example.org', $request->getLoginHint());
        $this->assertSame('the-subject', $request->getIdTokenHintSubject());
        $this->assertSame('issuer-state-value', $request->getIssuerState());
    }


    public function testDoesNotLogTheLoginHintValue(): void
    {
        // login_hint is routinely an email address or a username, so only its presence may be recorded.
        $loginHint = 'someone@example.org';

        $this->validatedAuthorizationRequest(ruleResults: [LoginHintRule::class => $loginHint]);

        $this->assertSecretsWereNotLogged($loginHint);
    }


    /**
     * PromptRule and MaxAgeRule may send the End-User to log in (prompt=login, an expired max_age). A request
     * naming a Credential Offer which can not be redeemed is refused before either runs, so nobody is asked to
     * log in for an offer which is then refused.
     */
    public function testChecksTheIssuerStateBeforeAnyRuleWhichMaySendTheUserToLogIn(): void
    {
        $this->validatedAuthorizationRequest();

        $issuerState = array_search(IssuerStateRule::class, $this->checkedRules, true);
        $this->assertIsInt($issuerState, 'The issuer state of an authorization request is not checked.');
        $this->assertLessThan(array_search(PromptRule::class, $this->checkedRules, true), $issuerState);
        $this->assertLessThan(array_search(MaxAgeRule::class, $this->checkedRules, true), $issuerState);
    }


    /**
     * A request following an offer which asks for a credential configuration the offer did not offer is refused
     * before the End-User is sent to log in, too. The rule judging that reads the scopes and the authorization
     * details, so it runs after the rules resolving them -- and those after IssuerStateRule, since a refused
     * scope goes to a redirect URI a non-registered wallet got accepted only with an issuer_state.
     */
    public function testChecksWhatAnOfferOfferedBeforeAnyRuleWhichMaySendTheUserToLogIn(): void
    {
        $this->validatedAuthorizationRequest();

        $position = function (string $rule): int {
            $position = array_search($rule, $this->checkedRules, true);
            $this->assertIsInt($position, sprintf('%s is not among the rules checked.', $rule));

            return $position;
        };
        $offered = $position(OfferedCredentialsRule::class);
        $this->assertLessThan($offered, $position(ScopeRule::class));
        $this->assertLessThan($offered, $position(AuthorizationDetailsRule::class));
        $this->assertLessThan($position(ScopeRule::class), $position(IssuerStateRule::class));
        $this->assertLessThan($position(PromptRule::class), $offered);
        $this->assertLessThan($position(MaxAgeRule::class), $offered);
    }


    public function testDoesNotLogTheIssuerStateValue(): void
    {
        // The issuer state is what lets a wallet redeem a Credential Offer, so only its presence may be recorded.
        $this->validatedAuthorizationRequest(ruleResults: [IssuerStateRule::class => self::ISSUER_STATE]);

        $this->assertSecretsWereNotLogged(self::ISSUER_STATE);
    }


    public function testBindsTheUsedClientIdAndRedirectUriWhenTheClientIsGeneric(): void
    {
        // A generic client stands in for many wallets, so the identifiers actually used have to be recorded
        // on the request; they are what the token endpoint later checks the redemption against.
        $request = $this->validatedAuthorizationRequest(
            client: $this->clientMock(isGeneric: true),
            ruleResults: [ClientIdRule::class => 'wallet-client-id'],
        );

        $this->assertSame('wallet-client-id', $request->getBoundClientId());
        $this->assertSame(self::REDIRECT_URI, $request->getBoundRedirectUri());
    }


    public function testDoesNotBindClientIdentifiersForARegisteredClient(): void
    {
        $request = $this->validatedAuthorizationRequest();

        $this->assertNull($request->getBoundClientId());
        $this->assertNull($request->getBoundRedirectUri());
    }


    public function testAddsCredentialConfigurationIdsFromAuthorizationDetailsToTheScopes(): void
    {
        $authorizationDetails = [
            ['type' => 'openid_credential', 'credential_configuration_id' => 'UniversityDegree'],
            ['type' => 'something_else', 'credential_configuration_id' => 'Ignored'],
        ];

        $request = $this->validatedAuthorizationRequest(
            ruleResults: [AuthorizationDetailsRule::class => $authorizationDetails],
        );

        $scopeIdentifiers = array_map(
            static fn(ScopeEntityInterface $scope): string => $scope->getIdentifier(),
            $request->getScopes(),
        );

        $this->assertContains('UniversityDegree', $scopeIdentifiers);
        $this->assertNotContains('Ignored', $scopeIdentifiers);
        $this->assertSame($authorizationDetails, $request->getAuthorizationDetails());
    }

    // Authorization request completion.

    public function testRefusesToCompleteAnAuthorizationRequestWithoutThisModulesUserEntity(): void
    {
        // The grant reads claims off the module's own UserEntity, so a bare league user entity is not
        // enough to issue a code from, and it must say so rather than fail later on a missing method.
        $authorizationRequest = $this->approvedAuthorizationRequest();
        $authorizationRequest->setUser($this->createMock(UserEntityInterface::class));

        $this->authCodeRepositoryMock->expects($this->never())->method('persistNewAuthCode');
        $this->expectException(LogicException::class);

        $this->sut()->completeOidcAuthorizationRequest($authorizationRequest);
    }


    public function testRedirectsWithAccessDeniedWhenTheUserDeclinedTheRequest(): void
    {
        $authorizationRequest = $this->approvedAuthorizationRequest();
        $authorizationRequest->setAuthorizationApproved(false);

        $this->authCodeRepositoryMock->expects($this->never())->method('persistNewAuthCode');

        try {
            $this->sut()->completeOidcAuthorizationRequest($authorizationRequest);
            $this->fail('A declined authorization must not produce an authorization code.');
        } catch (OAuthServerException $exception) {
            $this->assertSame('access_denied', $exception->getErrorType());
            $this->assertSame(self::REDIRECT_URI, $exception->getRedirectUri());
        }
    }


    public function testFallsBackToTheClientsRegisteredRedirectUriWhenTheRequestCarriesNone(): void
    {
        // The registered URI is the only one that was ever validated, so it is the only safe fallback.
        $client = $this->clientMock();
        $client->method('getRedirectUri')->willReturn([self::REDIRECT_URI, 'https://rp.example.org/other']);

        $authorizationRequest = $this->approvedAuthorizationRequest($client);
        $authorizationRequest->setRedirectUri(null);

        $this->expectAuthCodeToBeIssued($client);

        $response = $this->sut()->completeOidcAuthorizationRequest($authorizationRequest);

        $this->assertStringStartsWith(self::REDIRECT_URI . '?', $this->redirectUriOf($response));
    }


    public function testIssuesAnAuthorizationCodeAndRedirectsBackWithItAndTheState(): void
    {
        $authorizationRequest = $this->approvedAuthorizationRequest();
        $authorizationRequest->setState(self::STATE);

        $this->expectAuthCodeToBeIssued();

        $query = $this->redirectQueryOf($this->sut()->completeOidcAuthorizationRequest($authorizationRequest));

        $this->assertArrayHasKey('code', $query);
        $this->assertNotSame('', $query['code']);
        $this->assertSame(self::STATE, $query['state'], 'The state must be echoed back untouched.');
    }


    public function testNamesItselfAsTheIssuerInTheAuthorizationResponse(): void
    {
        // RFC 9207: the client compares iss with the issuer it sent the request to, to detect a mix-up.
        $this->expectAuthCodeToBeIssued();

        $query = $this->redirectQueryOf(
            $this->sut()->completeOidcAuthorizationRequest($this->approvedAuthorizationRequest()),
        );

        $this->assertSame(self::ISSUER, $query['iss'] ?? null);
    }


    public function testHandsTheIssuerToTheResponseModeTheRequestAskedFor(): void
    {
        // fragment and form_post render whatever parameters they are given, so the issuer has to be among them.
        $responseModeMock = $this->createMock(ResponseModeInterface::class);
        $responseModeMock->expects($this->once())
            ->method('buildResponse')
            ->with(self::REDIRECT_URI, $this->callback(
                static fn(array $params): bool => ($params['iss'] ?? null) === self::ISSUER,
            ))
            ->willReturn($this->createMock(AbstractResponseType::class));

        $authorizationRequest = $this->approvedAuthorizationRequest();
        $authorizationRequest->setResponseMode($responseModeMock);
        $this->expectAuthCodeToBeIssued();

        $this->sut()->completeOidcAuthorizationRequest($authorizationRequest);
    }


    public function testStampsTheIssuedCodeWithTheFlowItBelongsTo(): void
    {
        $verifiableCredentialRequest = $this->approvedAuthorizationRequest();
        $verifiableCredentialRequest->setIsVciRequest(true);

        $this->assertContains(
            FlowTypeEnum::VciAuthorizationCode,
            $this->argumentsTheAuthCodeWasBuiltFrom($verifiableCredentialRequest),
        );

        $this->setUp();

        $this->assertContains(
            FlowTypeEnum::OidcAuthorizationCode,
            $this->argumentsTheAuthCodeWasBuiltFrom($this->approvedAuthorizationRequest()),
        );
    }


    public function testRejectsAnUnexpectedAuthCodeRepositoryWhenIssuingACode(): void
    {
        $foreignRepository = $this->createMock(OAuth2AuthCodeRepositoryInterface::class);

        $this->expectException(OAuthServerException::class);

        $this->sut($foreignRepository)->completeOidcAuthorizationRequest($this->approvedAuthorizationRequest());
    }


    public function testDoesNotLogTheAuthorizationCodeItIssues(): void
    {
        $authorizationRequest = $this->approvedAuthorizationRequest();
        $this->expectAuthCodeToBeIssued();

        $query = $this->redirectQueryOf($this->sut()->completeOidcAuthorizationRequest($authorizationRequest));

        $this->assertSecretsWereNotLogged($query['code']);
    }


    public function testRoutesAnOidcAuthorizationRequestToTheOidcCompletionPath(): void
    {
        $authorizationRequest = $this->approvedAuthorizationRequest();
        $authorizationRequest->setState(self::STATE);
        $this->expectAuthCodeToBeIssued();

        $query = $this->redirectQueryOf($this->sut()->completeAuthorizationRequest($authorizationRequest));

        $this->assertArrayHasKey('code', $query);
        $this->assertSame(self::STATE, $query['state']);
    }


    public function testUsesTheRegisteredRedirectUriWhenTheClientHasExactlyOne(): void
    {
        // A client may register its redirect URI as a bare string rather than a list.
        $client = $this->clientMock();
        $client->method('getRedirectUri')->willReturn(self::REDIRECT_URI);

        $authorizationRequest = $this->approvedAuthorizationRequest($client);
        $authorizationRequest->setRedirectUri(null);

        $this->expectAuthCodeToBeIssued($client);

        $this->assertStringStartsWith(
            self::REDIRECT_URI . '?',
            $this->redirectUriOf($this->sut()->completeOidcAuthorizationRequest($authorizationRequest)),
        );
    }


    public function testRetriesWithAFreshIdentifierWhenTheGeneratedOneCollides(): void
    {
        // Identifiers are random, so a collision is rare but survivable: the grant must try again rather
        // than fail an otherwise valid authorization. Retrying with the same identifier would collide
        // again forever, so the identifiers themselves are what this asserts on, not just the retry count.
        $identifiers = [];
        $this->authCodeEntityFactoryMock->method('fromData')
            ->willReturnCallback(function (string $identifier) use (&$identifiers): AuthCodeEntity {
                $identifiers[] = $identifier;

                return $this->authCodeEntity();
            });

        $attempts = 0;
        $this->authCodeRepositoryMock->expects($this->exactly(2))
            ->method('persistNewAuthCode')
            ->willReturnCallback(function () use (&$attempts): void {
                $attempts++;

                if ($attempts === 1) {
                    throw UniqueTokenIdentifierConstraintViolationException::create();
                }
            });

        $query = $this->redirectQueryOf(
            $this->sut()->completeOidcAuthorizationRequest($this->approvedAuthorizationRequest()),
        );

        $this->assertArrayHasKey('code', $query);
        $this->assertCount(2, $identifiers);
        $this->assertNotSame(
            $identifiers[0],
            $identifiers[1],
            'A collision must be retried with a freshly generated identifier, not the one that collided.',
        );
    }


    /**
     * The two halves of the grant have to agree on the shape of the encrypted payload.
     *
     * Nothing else checks that. The authorization half writes the payload and the token half reads it back
     * by property name, so renaming a field on one side leaves the other silently reading a missing property
     * -- which PHP evaluates as null rather than failing. Issuing a code and then redeeming it is the only
     * assertion that holds both sides to the same format.
     */
    public function testACodeIssuedForAnAuthorizationRequestIsRedeemableAtTheTokenEndpoint(): void
    {
        $client = $this->clientMock();
        $authCode = $this->expectAuthCodeToBeIssued($client);

        // Every optional field is populated. The reader skips a field it cannot find rather than failing,
        // so a field left null here would make the test pass whether or not the two sides still agree on
        // its name -- which is the whole thing being guarded against.
        $claims = ['userinfo' => ['email' => null]];
        $authorizationRequest = $this->approvedAuthorizationRequest($client);
        $authorizationRequest->setCodeChallenge($this->codeChallenge());
        $authorizationRequest->setCodeChallengeMethod('S256');
        $authorizationRequest->setNonce('the-nonce');
        $authorizationRequest->setAuthTime(1_700_000_000);
        $authorizationRequest->setAcr('urn:mace:incommon:iap:silver');
        $authorizationRequest->setSessionId('the-session-id');
        $authorizationRequest->setClaims($claims);

        $query = $this->redirectQueryOf($this->sut()->completeOidcAuthorizationRequest($authorizationRequest));

        // Second half: redeem the code that was just issued, through the real token endpoint path.
        $this->authCodeRepositoryMock->method('findById')->willReturn($authCode);
        $this->rulesReturn(codeVerifier: self::CODE_VERIFIER);
        $accessToken = $this->expectAccessTokenToBeIssued();

        $responseType = $this->responseType();
        $responseType->expects($this->once())->method('setAccessToken')->with($accessToken);
        $responseType->expects($this->once())->method('setNonce')->with('the-nonce');
        $responseType->expects($this->once())->method('setAuthTime')->with(1_700_000_000);
        $responseType->expects($this->once())->method('setAcr')->with('urn:mace:incommon:iap:silver');
        $responseType->expects($this->once())->method('setSessionId')->with('the-session-id');

        $this->sut()->respondToAccessTokenRequest(
            $this->request([
                'code' => $query['code'],
                'redirect_uri' => self::REDIRECT_URI,
                'code_verifier' => self::CODE_VERIFIER,
            ]),
            $responseType,
            new DateInterval('PT5M'),
        );

        // Claims do not reach the response type; they are carried into the access token instead.
        $this->assertContains($claims, $this->accessTokenFactoryArguments);
    }

    // DPoP (RFC 9449): the token bound to the key of the request's proof; a code bound to a key.

    /**
     * @return array<string, array{?string}>
     */
    public static function proofProvider(): array
    {
        return [
            'with a proof' => ['thumbprint-of-the-proof-key'],
            'without one' => [null],
        ];
    }


    /**
     * The access token is bound to the key of the DPoP proof the token request came with (RFC 9449 section 5), which
     * the token endpoint checked before the grant ran; without a proof it is bound to nothing.
     */
    #[DataProvider('proofProvider')]
    public function testBindsTheAccessTokenToTheKeyOfTheRequestsProof(?string $proofJkt): void
    {
        $this->storedAuthCode();
        $this->expectAccessTokenToBeIssued();

        $this->sut()->respondToAccessTokenRequest(
            $this->request(proofJkt: $proofJkt),
            $this->responseType(),
            new DateInterval('PT5M'),
        );

        // The double receives the factory's arguments by position, and the DPoP key is the sixteenth.
        $this->assertSame($proofJkt, $this->accessTokenFactoryArguments[15]);
    }


    /**
     * A code the authorization request bound to a key (RFC 9449 section 10) is redeemed with a proof by that key,
     * and the token is bound to it.
     */
    public function testRedeemsACodeBoundToAKeyWithAProofByThatKey(): void
    {
        $this->storedAuthCode(dpopJkt: 'thumbprint-of-the-proof-key');
        $this->expectAccessTokenToBeIssued();
        $this->authCodeRepositoryMock->expects($this->once())->method('consumeAuthCode')->with(self::AUTH_CODE_ID);

        $this->sut()->respondToAccessTokenRequest(
            $this->request(proofJkt: 'thumbprint-of-the-proof-key'),
            $this->responseType(),
            new DateInterval('PT5M'),
        );

        $this->assertSame('thumbprint-of-the-proof-key', $this->accessTokenFactoryArguments[15]);
    }


    /**
     * @return array<string, array{?string, string}>
     */
    public static function unprovenKeyProvider(): array
    {
        return [
            'no proof' => [null, 'invalid_dpop_proof'],
            'a proof by another key' => ['thumbprint-of-another-key', 'invalid_grant'],
        ];
    }


    /**
     * A code bound to a key is refused without a proof (`invalid_dpop_proof`), and with a proof by another key,
     * which passed every check of its own (`invalid_grant`). The refusal comes before the code is looked at any
     * further: it spends neither the code nor the Credential Offer the code followed, and issues nothing.
     */
    #[DataProvider('unprovenKeyProvider')]
    public function testRefusesACodeBoundToAKeyWithoutAProofByThatKey(?string $proofJkt, string $expectedError): void
    {
        $this->storedAuthCode(
            issuerState: self::ISSUER_STATE,
            flowType: FlowTypeEnum::VciAuthorizationCode,
            dpopJkt: 'thumbprint-of-the-proof-key',
        );
        $this->authCodeRepositoryMock->expects($this->never())->method('consumeAuthCode');
        $this->issuerStateRepositoryMock->expects($this->never())->method('consume');
        $this->accessTokenRepositoryMock->expects($this->never())->method('persistNewAccessToken');

        $this->assertRejects($expectedError, $this->request(proofJkt: $proofJkt));
    }


    /**
     * A used code bound to a key, presented without a proof by that key, revokes nothing: whoever lacks the key
     * must not be able to cut off the client which holds it by replaying its spent code (RFC 6749 section 4.1.2's
     * revocation is for a replay by the code's holder).
     */
    #[DataProvider('unprovenKeyProvider')]
    public function testRevokesNothingForAUsedCodeBoundToAKeyWithoutAProofByThatKey(
        ?string $proofJkt,
        string $expectedError,
    ): void {
        $this->storedAuthCode(isRevoked: true, dpopJkt: 'thumbprint-of-the-proof-key');
        $this->accessTokenRepositoryMock->expects($this->never())->method('revokeByAuthCodeId');
        $this->refreshTokenRepositoryMock->expects($this->never())->method('revokeByAuthCodeId');

        $this->assertRejects($expectedError, $this->request(proofJkt: $proofJkt));
    }


    /**
     * Client authentication comes first: a client which fails it is answered `invalid_client` whether or not its
     * code is bound to a key.
     */
    public function testAuthenticatesTheClientBeforeLookingAtTheCodesKey(): void
    {
        $this->storedAuthCode(dpopJkt: 'thumbprint-of-the-proof-key');
        $this->requestRulesManagerMock = $this->createMock(RequestRulesManager::class);
        $this->requestRulesManagerMock->method('check')
            ->willThrowException(OAuthServerException::invalidClient($this->request()));

        $this->assertRejects('invalid_client', $this->request());
    }


    /**
     * A request which authenticates the client in no way at all is refused for that, before its code's key is
     * looked at.
     */
    public function testRefusesARequestWithoutClientAuthenticationBeforeLookingAtTheCodesKey(): void
    {
        $this->storedAuthCode(dpopJkt: 'thumbprint-of-the-proof-key');
        $this->rulesReturn(authenticationMethod: ClientAuthenticationMethodsEnum::None);

        $this->assertRejects('access_denied', $this->request());
    }


    /**
     * The proof reaches the grant only as the token endpoint put it on the request; anything else there is the
     * OP's own fault.
     */
    public function testAnswersSomethingElseInThePlaceOfTheProofAsAServerError(): void
    {
        $this->storedAuthCode();
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getParsedBody')->willReturn([
            'code' => $this->encryptPayload($this->payload()),
            'redirect_uri' => self::REDIRECT_URI,
        ]);
        $request->method('getAttribute')->willReturn('not a verified proof');

        $this->assertRejects('server_error', $request);
    }


    /**
     * @return array<string, array{?\SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum, ?string, string, int}>
     */
    public static function accessTokenLifetimeProvider(): array
    {
        return [
            'a VCI token bound to no key, configured longer than five minutes' =>
                [FlowTypeEnum::VciAuthorizationCode, null, 'PT1H', 300],
            'a VCI token bound to no key, configured shorter' =>
                [FlowTypeEnum::VciAuthorizationCode, null, 'PT2M', 120],
            'a VCI token bound to a key' =>
                [FlowTypeEnum::VciAuthorizationCode, 'thumbprint-of-the-proof-key', 'PT1H', 3600],
            'an OIDC token' => [FlowTypeEnum::OidcAuthorizationCode, null, 'PT1H', 600],
            'a code with no flow type recorded' => [null, 'thumbprint-of-the-proof-key', 'PT1H', 600],
        ];
    }


    /**
     * An access token for Verifiable Credential Issuance, by the code's stored flow type, lives what
     * vci_access_token_ttl says, and no longer than five minutes when it is bound to no key, whatever the
     * configuration says (OpenID4VCI 1.0 section 13.10). Any other lives the TTL the grant was enabled with.
     */
    #[DataProvider('accessTokenLifetimeProvider')]
    public function testChoosesTheAccessTokenLifetimeByTheCodesFlowAndBinding(
        ?FlowTypeEnum $flowType,
        ?string $proofJkt,
        string $configuredVciTtl,
        int $expectedSeconds,
    ): void {
        $this->vciAccessTokenTtl = $configuredVciTtl;
        $this->storedAuthCode(flowType: $flowType);
        $this->expectAccessTokenToBeIssued();

        $before = time();
        $this->sut()->respondToAccessTokenRequest(
            $this->request(proofJkt: $proofJkt),
            $this->responseType(),
            new DateInterval('PT10M'),
        );
        $after = time();

        $expiry = $this->accessTokenFactoryArguments[3];
        $this->assertInstanceOf(DateTimeImmutable::class, $expiry);
        $this->assertGreaterThanOrEqual($before + $expectedSeconds, $expiry->getTimestamp());
        $this->assertLessThanOrEqual($after + $expectedSeconds, $expiry->getTimestamp());
    }


    /**
     * The `dpop_jkt` of an authorization request (RFC 9449 section 10), which DpopJktRule checked, rides on the
     * request through the login.
     */
    public function testCarriesTheDpopJktOntoTheAuthorizationRequest(): void
    {
        $authorizationRequest = $this->validatedAuthorizationRequest(
            ruleResults: [DpopJktRule::class => 'thumbprint-of-the-key'],
        );

        $this->assertContains(DpopJktRule::class, $this->checkedRules);
        $this->assertInstanceOf(AuthorizationRequest::class, $authorizationRequest);
        $this->assertSame('thumbprint-of-the-key', $authorizationRequest->getDpopJkt());
    }


    /**
     * The code issued for an authorization request which named a key is bound to it.
     */
    public function testBindsTheIssuedCodeToTheKeyTheAuthorizationRequestNamed(): void
    {
        $authorizationRequest = $this->approvedAuthorizationRequest();
        $authorizationRequest->setDpopJkt('thumbprint-of-the-key');

        // The factory's arguments by position: the DPoP key is the fifteenth.
        $this->assertSame(
            'thumbprint-of-the-key',
            $this->argumentsTheAuthCodeWasBuiltFrom($authorizationRequest)[14],
        );
    }


    /**
     * @return array<string, array{bool, bool, \SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum, string}>
     */
    public static function requiredProofProvider(): array
    {
        return [
            'a client registered with dpop_bound_access_tokens' => [
                true,
                false,
                FlowTypeEnum::OidcAuthorizationCode,
                'A DPoP proof is required: the client is registered with dpop_bound_access_tokens.',
            ],
            'a code for credential issuance, with vci_require_dpop' => [
                false,
                true,
                FlowTypeEnum::VciAuthorizationCode,
                'A DPoP proof is required for credential issuance.',
            ],
        ];
    }


    /**
     * A proof is required of a client registered with dpop_bound_access_tokens (RFC 9449 section 5.2), and, with
     * vci_require_dpop, for a code issued for credential issuance. A request without one is refused as
     * `invalid_dpop_proof` before the code is looked at any further: it spends neither the code nor the Credential
     * Offer, and issues nothing.
     */
    #[DataProvider('requiredProofProvider')]
    public function testRefusesATokenRequestWithoutARequiredProof(
        bool $dpopBoundAccessTokens,
        bool $vciRequireDpop,
        FlowTypeEnum $flowType,
        string $expectedHint,
    ): void {
        $this->vciRequireDpop = $vciRequireDpop;
        $this->storedAuthCode(
            issuerState: self::ISSUER_STATE,
            flowType: $flowType,
            dpopBoundAccessTokens: $dpopBoundAccessTokens,
        );
        $this->authCodeRepositoryMock->expects($this->never())->method('consumeAuthCode');
        $this->issuerStateRepositoryMock->expects($this->never())->method('consume');
        $this->accessTokenRepositoryMock->expects($this->never())->method('persistNewAccessToken');

        $this->assertRejectsWithHint('invalid_dpop_proof', $expectedHint, $this->request());
    }


    /**
     * A used code presented without a proof its client or the module requires revokes nothing: the requirement
     * is checked before the code is.
     */
    #[DataProvider('requiredProofProvider')]
    public function testRevokesNothingForAUsedCodeWithoutARequiredProof(
        bool $dpopBoundAccessTokens,
        bool $vciRequireDpop,
        FlowTypeEnum $flowType,
        string $expectedHint,
    ): void {
        $this->vciRequireDpop = $vciRequireDpop;
        $this->storedAuthCode(isRevoked: true, flowType: $flowType, dpopBoundAccessTokens: $dpopBoundAccessTokens);
        $this->accessTokenRepositoryMock->expects($this->never())->method('revokeByAuthCodeId');
        $this->refreshTokenRepositoryMock->expects($this->never())->method('revokeByAuthCodeId');

        $this->assertRejectsWithHint('invalid_dpop_proof', $expectedHint, $this->request());
    }


    /**
     * @return array<string, array{bool, bool, ?\SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum, ?string}>
     */
    public static function proofNotRequiredOrPresentedProvider(): array
    {
        return [
            'a client registered with dpop_bound_access_tokens, with a proof' =>
                [true, false, FlowTypeEnum::OidcAuthorizationCode, 'thumbprint-of-the-proof-key'],
            'a code for credential issuance with vci_require_dpop, with a proof' =>
                [false, true, FlowTypeEnum::VciAuthorizationCode, 'thumbprint-of-the-proof-key'],
            'an OIDC code with vci_require_dpop, without one' =>
                [false, true, FlowTypeEnum::OidcAuthorizationCode, null],
            'a code with no flow type recorded, with vci_require_dpop, without one' => [false, true, null, null],
            'a code for credential issuance without vci_require_dpop, without one' =>
                [false, false, FlowTypeEnum::VciAuthorizationCode, null],
        ];
    }


    /**
     * The proof a client or the module requires is all it takes; vci_require_dpop reaches only a code whose stored
     * flow type is one for credential issuance.
     */
    #[DataProvider('proofNotRequiredOrPresentedProvider')]
    public function testIssuesWhenNoProofIsRequiredOrTheRequiredOneCame(
        bool $dpopBoundAccessTokens,
        bool $vciRequireDpop,
        ?FlowTypeEnum $flowType,
        ?string $proofJkt,
    ): void {
        $this->vciRequireDpop = $vciRequireDpop;
        $this->storedAuthCode(flowType: $flowType, dpopBoundAccessTokens: $dpopBoundAccessTokens);
        $this->expectAccessTokenToBeIssued();
        $this->authCodeRepositoryMock->expects($this->once())->method('consumeAuthCode')->with(self::AUTH_CODE_ID);

        $this->sut()->respondToAccessTokenRequest(
            $this->request(proofJkt: $proofJkt),
            $this->responseType(),
            new DateInterval('PT5M'),
        );

        $this->assertSame($proofJkt, $this->accessTokenFactoryArguments[15]);
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
            $this->userRepositoryMock,
            $this->subjectResolverMock,
            $this->accessTokenClaimsResolverMock,
            $this->moduleConfigMock,
            $this->issuerStateRepositoryMock,
        );

        $grant->setEncryptionKey($this->encryptionKey);
        $grant->setScopeRepository($this->scopeRepositoryMock);
        // AuthorizationServerFactory registers every grant through enableGrantType(), which sets the default
        // scope on it. Without this the property stays uninitialized, which is a state the grant never
        // reaches in production.
        $grant->setDefaultScope('');

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
     * As assertRejects(), and with the hint the client is given.
     */
    private function assertRejectsWithHint(
        string $expectedErrorType,
        string $expectedHint,
        ServerRequestInterface $request,
    ): void {
        try {
            $this->sut()->respondToAccessTokenRequest($request, $this->responseType(), new DateInterval('PT5M'));
        } catch (OAuthServerException $exception) {
            $this->assertSame($expectedErrorType, $exception->getErrorType());
            $this->assertSame($expectedHint, $exception->getHint());

            return;
        }

        $this->fail(sprintf('Expected the token request to be rejected with "%s".', $expectedErrorType));
    }


    /**
     * @param array<string,mixed> $parsedBody
     * @param string|null $proofJkt The key of a DPoP proof the token endpoint verified for the request, if any.
     */
    private function request(
        ?array $parsedBody = null,
        bool $withRedirectUri = true,
        ?string $proofJkt = null,
    ): ServerRequestInterface {
        if ($parsedBody === null) {
            $parsedBody = ['code' => $this->encryptPayload($this->payload())];

            if ($withRedirectUri) {
                $parsedBody['redirect_uri'] = self::REDIRECT_URI;
            }
        }

        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getParsedBody')->willReturn($parsedBody);

        $verifiedDpopProof = $proofJkt === null ?
        null :
        new VerifiedDpopProof($this->createStub(DpopProof::class), $proofJkt);
        $request->method('getAttribute')->willReturnCallback(
            fn(string $name): ?VerifiedDpopProof =>
                $name === DpopProofVerifier::ATTRIBUTE_VERIFIED_PROOF ? $verifiedDpopProof : null,
        );

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
        ?string $issuerState = null,
        ?FlowTypeEnum $flowType = null,
        ?string $dpopJkt = null,
        bool $dpopBoundAccessTokens = false,
    ): AuthCodeEntity {
        $client = $this->createMock(ClientEntity::class);
        $client->method('getIdentifier')->willReturn(self::CLIENT_ID);
        $client->method('isGeneric')->willReturn($isGeneric);
        $client->method('getGrantTypes')->willReturn($grantTypes ?? ['authorization_code']);
        $client->method('getDpopBoundAccessTokens')->willReturn($dpopBoundAccessTokens);

        $authCode = new AuthCodeEntity(
            self::AUTH_CODE_ID,
            $client,
            [],
            new DateTimeImmutable('+1 hour'),
            self::USER_ID,
            self::REDIRECT_URI,
            isRevoked: $isRevoked,
            flowTypeEnum: $flowType,
            boundClientId: self::CLIENT_ID,
            boundRedirectUri: self::REDIRECT_URI,
            issuerState: $issuerState,
            dpopJkt: $dpopJkt,
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


    /**
     * Drive validateAuthorizationRequestWithRequestRules() with a full set of rule results.
     *
     * The method reads roughly fifteen rule results, most with getOrFail(), so every one has to be present
     * or the failure is a missing key rather than the behavior under test. Defaults stand in for "the rule
     * ran and found nothing"; `ruleResults` overrides individual ones by rule class.
     *
     * @param \League\OAuth2\Server\Entities\ScopeEntityInterface[]|null $scopes
     * @param array<class-string,mixed> $ruleResults
     */
    private function validatedAuthorizationRequest(
        ?array $scopes = null,
        ?ClientEntity $client = null,
        bool $isVciRequest = false,
        ?string $nonce = null,
        array $ruleResults = [],
    ): OAuth2AuthorizationRequest {
        $client ??= $this->clientMock();
        $scopes ??= [new ScopeEntity('openid')];

        $defaults = [
            ScopeRule::class => $scopes,
            CodeChallengeRule::class => null,
            CodeChallengeMethodRule::class => null,
            AcrValuesRule::class => null,
            UiLocalesRule::class => null,
            LoginHintRule::class => null,
            IdTokenHintRule::class => null,
            MaxAgeRule::class => null,
            RequestedClaimsRule::class => null,
            IssuerStateRule::class => null,
            AuthorizationDetailsRule::class => null,
            ClientIdRule::class => null,
            DpopJktRule::class => null,
            ResponseModeRule::class => new QueryResponseMode(),
        ];

        $checked = new ResultBag();
        foreach (array_merge($defaults, $ruleResults) as $rule => $value) {
            // A rule class that is not imported still yields a `::class` string, just one in this namespace,
            // and the bag would then be missing the entry the grant asks for. Fail on the cause instead.
            $this->assertTrue(class_exists($rule), sprintf('Rule class "%s" does not exist.', $rule));

            $checked->add(new Result($rule, $value));
        }

        $this->requestRulesManagerMock = $this->createMock(RequestRulesManager::class);
        $this->requestRulesManagerMock->method('check')->willReturnCallback(
            function (ServerRequestInterface $request, array $rules) use ($checked): ResultBag {
                $this->checkedRules = $rules;

                return $checked;
            },
        );

        $this->requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $this->resolverReturnsTheRequestBody($this->requestParamsResolverMock);
        $this->requestParamsResolverMock->method('isVciAuthorizationCodeRequest')->willReturn($isVciRequest);
        $this->requestParamsResolverMock->method('getAsStringBasedOnAllowedMethods')
            ->willReturnCallback(
                static fn(string $parameter): ?string => $parameter === ParamsEnum::Nonce->value ? $nonce : null,
            );

        // What the caller has already resolved before these rules run.
        $incoming = new ResultBag();
        $incoming->add(new Result(ClientRedirectUriRule::class, self::REDIRECT_URI));
        $incoming->add(new Result(StateRule::class, self::STATE));
        $incoming->add(new Result(ClientRule::class, $client));
        $incoming->add(new Result(ResponseModeRule::class, new QueryResponseMode()));

        return $this->sut()->validateAuthorizationRequestWithRequestRules($this->request([]), $incoming);
    }


    /**
     * @param \League\OAuth2\Server\Entities\ScopeEntityInterface[] $scopes
     */
    private function oAuth2AuthorizationRequest(array $scopes): OAuth2AuthorizationRequest
    {
        $request = new OAuth2AuthorizationRequest();
        $request->setScopes($scopes);

        return $request;
    }


    /**
     * An authorization request in the state the authorization screen leaves it in: a user is attached and
     * the user approved it. Individual tests take it back apart to cover the paths that do not get here.
     */
    private function approvedAuthorizationRequest(?ClientEntity $client = null): AuthorizationRequest
    {
        $request = new AuthorizationRequest();
        $request->setGrantTypeId('authorization_code');
        $request->setClient($client ?? $this->clientMock());
        $request->setRedirectUri(self::REDIRECT_URI);
        $request->setScopes([new ScopeEntity('openid')]);
        $request->setUser(new UserEntity(self::USER_ID, new DateTimeImmutable(), new DateTimeImmutable()));
        $request->setAuthorizationApproved(true);

        return $request;
    }


    private function clientMock(bool $isGeneric = false, ?array $grantTypes = null): ClientEntity&MockObject
    {
        $client = $this->createMock(ClientEntity::class);
        $client->method('getIdentifier')->willReturn(self::CLIENT_ID);
        $client->method('isGeneric')->willReturn($isGeneric);
        $client->method('getGrantTypes')->willReturn($grantTypes ?? ['authorization_code']);

        return $client;
    }


    private function authCodeEntity(?ClientEntity $client = null, bool $isRevoked = false): AuthCodeEntity
    {
        return new AuthCodeEntity(
            self::AUTH_CODE_ID,
            $client ?? $this->clientMock(),
            [new ScopeEntity('openid')],
            new DateTimeImmutable('+1 hour'),
            self::USER_ID,
            self::REDIRECT_URI,
            isRevoked: $isRevoked,
            boundClientId: self::CLIENT_ID,
            boundRedirectUri: self::REDIRECT_URI,
        );
    }


    /**
     * Complete the request and report what the auth code factory was called with.
     *
     * The grant passes several of these by name, and PHPUnit records an invocation positionally, so the
     * arguments are returned as a flat list and asserted against by value rather than by parameter name.
     *
     * @return array<int,mixed>
     */
    private function argumentsTheAuthCodeWasBuiltFrom(AuthorizationRequest $authorizationRequest): array
    {
        $captured = [];

        $this->authCodeEntityFactoryMock->method('fromData')
            ->willReturnCallback(
                function (...$arguments) use (&$captured): AuthCodeEntity {
                    $captured = $arguments;

                    return $this->authCodeEntity();
                },
            );

        $this->sut()->completeOidcAuthorizationRequest($authorizationRequest);

        return $captured;
    }


    private function expectAuthCodeToBeIssued(?ClientEntity $client = null): AuthCodeEntity
    {
        $authCode = $this->authCodeEntity($client);

        $this->authCodeEntityFactoryMock->method('fromData')->willReturn($authCode);
        $this->authCodeRepositoryMock->expects($this->once())
            ->method('persistNewAuthCode')
            ->with($authCode);

        return $authCode;
    }


    /**
     * The base64url encoded SHA-256 of the shared verifier, per RFC 7636 section 4.2.
     */
    private function codeChallenge(): string
    {
        return strtr(rtrim(base64_encode(hash('sha256', self::CODE_VERIFIER, true)), '='), '+/', '-_');
    }


    private function redirectUriOf(AbstractResponseType $response): string
    {
        return $response->generateHttpResponse(new Response())->getHeaderLine('location');
    }


    /**
     * The query parameters the client is redirected back with.
     *
     * @return array<string,string>
     */
    private function redirectQueryOf(AbstractResponseType $response): array
    {
        parse_str((string)parse_url($this->redirectUriOf($response), PHP_URL_QUERY), $query);

        /** @var array<string,string> $query */
        return $query;
    }


    private function expectAccessTokenToBeIssued(): AccessTokenEntity&MockObject
    {
        $accessToken = $this->createMock(AccessTokenEntity::class);

        $this->accessTokenEntityFactoryMock->method('fromData')
            ->willReturnCallback(function (...$arguments) use ($accessToken): AccessTokenEntity {
                $this->accessTokenFactoryArguments = $arguments;

                return $accessToken;
            });
        $this->accessTokenRepositoryMock->expects($this->once())
            ->method('persistNewAccessToken')
            ->with($accessToken);

        return $accessToken;
    }


    /**
     * @return \League\OAuth2\Server\ResponseTypes\ResponseTypeInterface&\PHPUnit\Framework\MockObject\MockObject
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


    /**
     * Record, in order, the revocations by authorization code and the release of an issuer state, which the
     * recovery from a failed issuance makes.
     */
    private function recordRecoveryCalls(): ArrayObject
    {
        $calls = new ArrayObject();
        $this->accessTokenRepositoryMock->method('revokeByAuthCodeId')->willReturnCallback(
            function (string $authCodeId) use ($calls): void {
                $calls->append(['access', $authCodeId]);
            },
        );
        $this->refreshTokenRepositoryMock->method('revokeByAuthCodeId')->willReturnCallback(
            function (string $authCodeId) use ($calls): void {
                $calls->append(['refresh', $authCodeId]);
            },
        );
        $this->issuerStateRepositoryMock->method('release')->willReturnCallback(
            function (string $value) use ($calls): void {
                $calls->append(['release', $value]);
            },
        );

        return $calls;
    }


    /**
     * Record, among the calls above, each authorization code the grant consumes. Whether it is still there to
     * consume is $authCodeIsConsumable's to say: the stub setUp() registered first answers.
     */
    private function recordConsumedAuthCodes(ArrayObject $calls): void
    {
        $this->authCodeRepositoryMock->method('consumeAuthCode')->willReturnCallback(
            function (string $authCodeId) use ($calls): bool {
                $calls->append(['consume', $authCodeId]);

                return $this->authCodeIsConsumable;
            },
        );
    }


    private function captureLogs(string $level): void
    {
        $this->loggerServiceMock->method($level)->willReturnCallback(
            function (string|Stringable $message, array $context = []) use ($level): void {
                $this->logRecords[] = ['level' => $level, 'message' => (string)$message, 'context' => $context];
            },
        );
    }


    /**
     * The token request ends in exactly this throwable, not in one raised while recovering from it.
     */
    private function assertTheCallerGets(Throwable $failure): void
    {
        try {
            $this->sut()->respondToAccessTokenRequest(
                $this->request(),
                $this->responseType(),
                new DateInterval('PT5M'),
            );
        } catch (Throwable $exception) {
            $this->assertSame($failure, $exception);

            return;
        }

        $this->fail('The failure to issue the token must reach the caller.');
    }


    /**
     * One error names both failures, the one recovered from and the recovery's own, against the code; nothing
     * logged on the way names the offer's issuer state.
     */
    private function assertRecoveryFailureWasLogged(string $failure, string $recoveryFailure): void
    {
        $records = array_values(array_filter(
            $this->logRecords,
            fn(array $record): bool => str_contains((string)$record['message'], 'giving back the Credential Offer'),
        ));

        $this->assertCount(1, $records);
        $this->assertSame('error', $records[0]['level']);
        $this->assertSame(
            [
                'client_id' => self::CLIENT_ID,
                'auth_code_id' => self::AUTH_CODE_ID,
                'exception' => $failure,
                'recovery_exception' => $recoveryFailure,
            ],
            $records[0]['context'],
        );
        $this->assertSecretsWereNotLogged(self::ISSUER_STATE);
    }


    private function assertSecretsWereNotLogged(string ...$secrets): void
    {
        $logs = json_encode($this->logRecords, JSON_THROW_ON_ERROR);

        foreach ($secrets as $secret) {
            $this->assertStringNotContainsString($secret, $logs);
        }
    }
}
