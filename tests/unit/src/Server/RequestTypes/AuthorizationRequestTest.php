<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestTypes;

use Closure;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest as OAuth2AuthorizationRequest;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum;
use SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;

#[CoversClass(AuthorizationRequest::class)]
#[AllowMockObjectsWithoutExpectations]
class AuthorizationRequestTest extends TestCase
{
    protected const string REDIRECT_URI = 'https://rp.example.org/callback';

    protected const string STATE = 'state-1';

    protected const string CODE_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';


    /**
     * An OAuth2 authorization request with everything the OIDC one is built from.
     */
    protected function oAuth2AuthorizationRequest(
        ?string $codeChallenge = self::CODE_CHALLENGE,
        ?string $state = self::STATE,
    ): OAuth2AuthorizationRequest {
        $oAuth2AuthorizationRequest = new OAuth2AuthorizationRequest();
        $oAuth2AuthorizationRequest->setGrantTypeId('authorization_code');
        $oAuth2AuthorizationRequest->setClient($this->createMock(ClientEntityInterface::class));
        $oAuth2AuthorizationRequest->setRedirectUri(self::REDIRECT_URI);
        $oAuth2AuthorizationRequest->setScopes([$this->createMock(ScopeEntityInterface::class)]);

        if ($codeChallenge !== null) {
            $oAuth2AuthorizationRequest->setCodeChallenge($codeChallenge);
            $oAuth2AuthorizationRequest->setCodeChallengeMethod('S256');
        }

        if ($state !== null) {
            $oAuth2AuthorizationRequest->setState($state);
        }

        return $oAuth2AuthorizationRequest;
    }


    /**
     * The conversion is where an OAuth2 request becomes an OIDC one, and anything it forgets to carry is
     * lost silently: the property it should have landed in is nullable, so the request simply looks like
     * one which never asked for it.
     */
    public function testCarriesEverythingOverFromTheOAuth2Request(): void
    {
        $oAuth2AuthorizationRequest = $this->oAuth2AuthorizationRequest();

        $authorizationRequest = AuthorizationRequest::fromOAuth2AuthorizationRequest($oAuth2AuthorizationRequest);

        $this->assertSame($oAuth2AuthorizationRequest->getGrantTypeId(), $authorizationRequest->getGrantTypeId());
        $this->assertSame($oAuth2AuthorizationRequest->getClient(), $authorizationRequest->getClient());
        $this->assertSame($oAuth2AuthorizationRequest->getRedirectUri(), $authorizationRequest->getRedirectUri());
        $this->assertSame($oAuth2AuthorizationRequest->getScopes(), $authorizationRequest->getScopes());
        $this->assertSame($oAuth2AuthorizationRequest->getState(), $authorizationRequest->getState());
        $this->assertSame(
            $oAuth2AuthorizationRequest->getCodeChallenge(),
            $authorizationRequest->getCodeChallenge(),
        );
        $this->assertSame(
            $oAuth2AuthorizationRequest->getCodeChallengeMethod(),
            $authorizationRequest->getCodeChallengeMethod(),
        );
    }


    /**
     * A request which used neither PKCE nor `state` produces one which asked for neither, rather than one
     * carrying an empty value for them.
     */
    public function testCarriesNoCodeChallengeOrStateWhenTheRequestHadNone(): void
    {
        $authorizationRequest = AuthorizationRequest::fromOAuth2AuthorizationRequest(
            $this->oAuth2AuthorizationRequest(codeChallenge: null, state: null),
        );

        $this->assertNull($authorizationRequest->getCodeChallenge());
        $this->assertNull($authorizationRequest->getCodeChallengeMethod());
        $this->assertNull($authorizationRequest->getState());
    }


    /**
     * Whether an access token belongs in the authorization response is decided by the response type, and
     * only the implicit and hybrid flows which asked for `token` get one there.
     */
    #[DataProvider('responseTypeProvider')]
    public function testKnowsWhetherAnAccessTokenBelongsInTheAuthorizationResponse(
        ?string $responseType,
        bool $expected,
    ): void {
        $authorizationRequest = new AuthorizationRequest();

        if ($responseType !== null) {
            $authorizationRequest->setResponseType($responseType);
        }

        $this->assertSame(
            $expected,
            $authorizationRequest->shouldReturnAccessTokenInAuthorizationResponse(),
        );
    }


    /**
     * @return array<string,array{0: ?string, 1: bool}>
     */
    public static function responseTypeProvider(): array
    {
        return [
            'no response type resolved yet' => [null, false],
            'code' => ['code', false],
            'id_token' => ['id_token', false],
            'token' => ['token', true],
            'id_token token' => ['id_token token', true],
            'code id_token' => ['code id_token', false],
            'code id_token token' => ['code id_token token', true],
            // Matched as a whole value rather than as a substring, or `not_a_token` would qualify.
            'a response type merely containing the word' => ['not_a_token', false],
        ];
    }


    /**
     * A fresh request has asked for nothing, and the defaults say so rather than standing in for an
     * answer: `null` is "not established", which is not the same as `false`.
     */
    public function testAFreshRequestCarriesNothing(): void
    {
        $authorizationRequest = new AuthorizationRequest();

        $this->assertNull($authorizationRequest->getNonce());
        $this->assertNull($authorizationRequest->getAuthTime());
        $this->assertNull($authorizationRequest->getClaims());
        $this->assertNull($authorizationRequest->getResponseType());
        $this->assertNull($authorizationRequest->getResponseMode());
        $this->assertNull($authorizationRequest->getIsCookieBasedAuthn());
        $this->assertNull($authorizationRequest->getAuthSourceId());
        $this->assertNull($authorizationRequest->getRequestedAcrValues());
        $this->assertNull($authorizationRequest->getUiLocales());
        $this->assertNull($authorizationRequest->getLoginHint());
        $this->assertNull($authorizationRequest->getIdTokenHintSubject());
        $this->assertNull($authorizationRequest->getAcr());
        $this->assertNull($authorizationRequest->getSessionId());
        $this->assertNull($authorizationRequest->getIssuerState());
        $this->assertNull($authorizationRequest->getFlowType());
        $this->assertNull($authorizationRequest->getAuthorizationDetails());
        $this->assertNull($authorizationRequest->getBoundClientId());
        $this->assertNull($authorizationRequest->getBoundRedirectUri());

        // Both of these decide what is issued, so neither may default to yes.
        $this->assertFalse($authorizationRequest->getAddClaimsToIdToken());
        $this->assertFalse($authorizationRequest->isVciRequest());
    }


    /**
     * This request is carried across the login redirect and read back on the other side, so every value
     * put into it has to come out of the property it was meant for. A setter writing to a neighbouring
     * property is invisible until something downstream reads the wrong claim.
     *
     * @param \Closure(\SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest, mixed): void $set
     * @param \Closure(\SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest): mixed $get
     */
    #[DataProvider('accessorProvider')]
    public function testRoundTripsWhatIsPutIntoIt(Closure $set, Closure $get, mixed $value): void
    {
        $authorizationRequest = new AuthorizationRequest();

        $set($authorizationRequest, $value);

        $this->assertSame($value, $get($authorizationRequest));
    }


    /**
     * @return array<string,array{0: \Closure, 1: \Closure, 2: mixed}>
     */
    public static function accessorProvider(): array
    {
        return [
            'nonce' => [
                static fn(AuthorizationRequest $r, mixed $v): mixed => $r->setNonce((string)$v),
                static fn(AuthorizationRequest $r): mixed => $r->getNonce(),
                'nonce-1',
            ],
            'auth time' => [
                static fn(AuthorizationRequest $r, mixed $v): mixed => $r->setAuthTime((int)$v),
                static fn(AuthorizationRequest $r): mixed => $r->getAuthTime(),
                1735689600,
            ],
            'claims' => [
                static fn(AuthorizationRequest $r, mixed $v): mixed => $r->setClaims((array)$v),
                static fn(AuthorizationRequest $r): mixed => $r->getClaims(),
                ['id_token' => ['acr' => null]],
            ],
            'add claims to ID token' => [
                static fn(AuthorizationRequest $r, mixed $v): mixed => $r->setAddClaimsToIdToken((bool)$v),
                static fn(AuthorizationRequest $r): mixed => $r->getAddClaimsToIdToken(),
                true,
            ],
            'response type' => [
                static fn(AuthorizationRequest $r, mixed $v): mixed => $r->setResponseType((string)$v),
                static fn(AuthorizationRequest $r): mixed => $r->getResponseType(),
                'code id_token',
            ],
            'is cookie based authn' => [
                static fn(AuthorizationRequest $r, mixed $v): mixed => $r->setIsCookieBasedAuthn((bool)$v),
                static fn(AuthorizationRequest $r): mixed => $r->getIsCookieBasedAuthn(),
                true,
            ],
            'auth source ID' => [
                static fn(AuthorizationRequest $r, mixed $v): mixed => $r->setAuthSourceId((string)$v),
                static fn(AuthorizationRequest $r): mixed => $r->getAuthSourceId(),
                'default-sp',
            ],
            'requested ACR values' => [
                static fn(AuthorizationRequest $r, mixed $v): mixed => $r->setRequestedAcrValues((array)$v),
                static fn(AuthorizationRequest $r): mixed => $r->getRequestedAcrValues(),
                ['values' => ['1', '0']],
            ],
            'UI locales' => [
                static fn(AuthorizationRequest $r, mixed $v): mixed => $r->setUiLocales((string)$v),
                static fn(AuthorizationRequest $r): mixed => $r->getUiLocales(),
                'hr en',
            ],
            'login hint' => [
                static fn(AuthorizationRequest $r, mixed $v): mixed => $r->setLoginHint((string)$v),
                static fn(AuthorizationRequest $r): mixed => $r->getLoginHint(),
                'user@example.org',
            ],
            'ID token hint subject' => [
                static fn(AuthorizationRequest $r, mixed $v): mixed => $r->setIdTokenHintSubject((string)$v),
                static fn(AuthorizationRequest $r): mixed => $r->getIdTokenHintSubject(),
                'subject-1',
            ],
            'ACR' => [
                static fn(AuthorizationRequest $r, mixed $v): mixed => $r->setAcr((string)$v),
                static fn(AuthorizationRequest $r): mixed => $r->getAcr(),
                '1',
            ],
            'session ID' => [
                static fn(AuthorizationRequest $r, mixed $v): mixed => $r->setSessionId((string)$v),
                static fn(AuthorizationRequest $r): mixed => $r->getSessionId(),
                'session-1',
            ],
            'is VCI request' => [
                static fn(AuthorizationRequest $r, mixed $v): mixed => $r->setIsVciRequest((bool)$v),
                static fn(AuthorizationRequest $r): mixed => $r->isVciRequest(),
                true,
            ],
            'issuer state' => [
                static fn(AuthorizationRequest $r, mixed $v): mixed => $r->setIssuerState((string)$v),
                static fn(AuthorizationRequest $r): mixed => $r->getIssuerState(),
                'issuer-state-1',
            ],
            'flow type' => [
                static fn(AuthorizationRequest $r, mixed $v): mixed => $r->setFlowType(
                    $v instanceof FlowTypeEnum ? $v : null,
                ),
                static fn(AuthorizationRequest $r): mixed => $r->getFlowType(),
                FlowTypeEnum::VciAuthorizationCode,
            ],
            'authorization details' => [
                static fn(AuthorizationRequest $r, mixed $v): mixed => $r->setAuthorizationDetails((array)$v),
                static fn(AuthorizationRequest $r): mixed => $r->getAuthorizationDetails(),
                [['type' => 'openid_credential']],
            ],
            'bound client ID' => [
                static fn(AuthorizationRequest $r, mixed $v): mixed => $r->setBoundClientId((string)$v),
                static fn(AuthorizationRequest $r): mixed => $r->getBoundClientId(),
                'client-1',
            ],
            'bound redirect URI' => [
                static fn(AuthorizationRequest $r, mixed $v): mixed => $r->setBoundRedirectUri((string)$v),
                static fn(AuthorizationRequest $r): mixed => $r->getBoundRedirectUri(),
                self::REDIRECT_URI,
            ],
        ];
    }


    /**
     * The response mode decides how the authorization response reaches the client, so it is carried as
     * the object which knows how to do that rather than as its name.
     */
    public function testCarriesTheResponseMode(): void
    {
        $responseModeMock = $this->createMock(ResponseModeInterface::class);
        $authorizationRequest = new AuthorizationRequest();

        $authorizationRequest->setResponseMode($responseModeMock);

        $this->assertSame($responseModeMock, $authorizationRequest->getResponseMode());
    }
}
