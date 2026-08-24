<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\Grants;

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
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
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
use SimpleSAML\Module\oidc\Repositories\AuthCodeRepository;
use SimpleSAML\Module\oidc\Repositories\Interfaces\AccessTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Repositories\Interfaces\RefreshTokenRepositoryInterface;
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
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\IdTokenHintRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\IssuerStateRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\LoginHintRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\MaxAgeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequestedClaimsRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ResponseModeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ScopeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\UiLocalesRule;
use SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
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
use SimpleSAML\OpenID\Core\IdTokenHint;
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

    /** What the access token factory was last called with, for assertions on values with no other outlet. */
    private array $accessTokenFactoryArguments = [];


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
        // The real array helper rather than a double: findByCallback() is a pure function, and stubbing it
        // would mean deciding in the test what counts as an OIDC request, which is the thing under test.
        $this->helpersMock->method('arr')->willReturn(new Arr());
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
        $this->requestRulesManagerMock->method('check')->willReturn($checked);

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
