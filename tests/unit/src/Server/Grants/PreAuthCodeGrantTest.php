<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\Grants;

use Closure;
use DateInterval;
use DateTimeImmutable;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface as OAuth2AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface as OAuth2ClientEntityInterface;
use League\OAuth2\Server\EventEmitting\EventEmitter;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface as OAuth2AuthCodeRepositoryInterface;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest as OAuth2AuthorizationRequest;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use ReflectionClassConstant;
use ReflectionMethod;
use RuntimeException;
use SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\AuthCodeEntity;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\RefreshTokenEntityInterface;
use SimpleSAML\Module\oidc\Factories\Entities\AccessTokenEntityFactory;
use SimpleSAML\Module\oidc\Factories\Entities\AuthCodeEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Repositories\AuthCodeRepository;
use SimpleSAML\Module\oidc\Repositories\Interfaces\AccessTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Repositories\Interfaces\RefreshTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\Grants\PreAuthCodeGrant;
use SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\AuthorizationDetailsRule;
use SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Server\TokenIssuers\RefreshTokenIssuer;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;
use Stringable;

/**
 * The token endpoint half of the OpenID for Verifiable Credential Issuance pre-authorized code flow.
 *
 * A pre-authorized code is issued out of band, inside a credential offer, and carries the holder, the client
 * and, optionally, a transaction code the wallet has to present with it. This grant redeems it: it finds the
 * stored code, checks that it is a pre-authorized one, unexpired and unrevoked, checks the transaction code
 * when the stored code carries one, runs the authorization details rule, consumes the code with the
 * repository's conditional update as the replay guard, and only then issues the access token, bound to the
 * client id presented and to the authorization details. A pre-authorized code is never requested through
 * the authorization endpoint, so the grant claims no authorization request and the module's four hooks
 * which would carry one towards a code all throw; League's own validateAuthorizationRequest() is inherited
 * untouched, but the module's server never reaches it for a grant which claims no request.
 *
 * The four tests at the top predate this file's coverage pass and pin the replay guard: consumption before
 * issuance, a second redemption refused, an invalid transaction code refused before consumption, and no
 * attempt to give the code back when token persistence fails after it. The rest pin each refusal with its
 * error type and hint, and its log line where the grant writes one, what the issued token is made of, and
 * the closed hooks. The client id presented is not checked against the code's client; the source marks
 * client authentication as an open question, and the tests keep the two equal rather than pin either
 * answer.
 */
#[CoversClass(PreAuthCodeGrant::class)]
#[UsesClass(AuthCodeEntity::class)]
#[UsesClass(AuthorizationRequest::class)]
#[UsesClass(Result::class)]
#[UsesClass(ResultBag::class)]
#[AllowMockObjectsWithoutExpectations]
class PreAuthCodeGrantTest extends TestCase
{
    private const string PRE_AUTHORIZED_CODE = 'pre-authorized-code-secret';

    private const string TRANSACTION_CODE = '1234';

    private const string CLIENT_ID = 'wallet-client';

    private const string USER_ID = 'user-id';

    private const array AUTHORIZATION_DETAILS = [
        ['type' => 'openid_credential', 'credential_configuration_id' => 'UniversityDegreeCredential'],
    ];

    /** The one hint an unknown code and a consumed one share, so that the answer does not tell them apart. */
    private const string INVALID_CODE_HINT = 'Invalid pre-authorized code.';


    private AuthCodeRepository&MockObject $authCodeRepositoryMock;

    private AccessTokenRepositoryInterface&MockObject $accessTokenRepositoryMock;

    private RefreshTokenRepositoryInterface&MockObject $refreshTokenRepositoryMock;

    private RequestRulesManager&MockObject $requestRulesManagerMock;

    private RequestParamsResolver&MockObject $requestParamsResolverMock;

    private AccessTokenEntityFactory&MockObject $accessTokenEntityFactoryMock;

    private AuthCodeEntityFactory&MockObject $authCodeEntityFactoryMock;

    private RefreshTokenIssuer&MockObject $refreshTokenIssuerMock;

    private Helpers&MockObject $helpersMock;

    private LoggerService&MockObject $loggerServiceMock;

    private ServerRequestInterface&MockObject $requestMock;

    /** The client the pre-authorized code was issued to. */
    private ClientEntity&MockObject $clientMock;

    /** @var array<int, array{level: string, message: string, context: array}> */
    private array $logRecords = [];

    /** @var string[] The request parameters the grant asked the resolver for, in order. */
    private array $askedParameters = [];


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
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        $this->requestMock = $this->createMock(ServerRequestInterface::class);
        $this->clientMock = $this->createMock(ClientEntity::class);
        $this->clientMock->method('getIdentifier')->willReturn(self::CLIENT_ID);

        $this->captureLogs('debug');
        $this->captureLogs('notice');
        $this->captureLogs('warning');
        $this->captureLogs('error');
    }


    public function testRedeemsPreAuthorizedCodeOnlyAfterAtomicConsumption(): void
    {
        $this->configureRequestParameters(self::TRANSACTION_CODE);
        $this->withNoAuthorizationDetails();
        $authCode = $this->preAuthorizedCode(self::TRANSACTION_CODE);
        $accessToken = $this->createMock(AccessTokenEntity::class);
        $responseType = $this->createMock(ResponseTypeInterface::class);
        $operationOrder = [];

        $this->authCodeRepositoryMock->expects($this->once())
            ->method('findById')
            ->with(self::PRE_AUTHORIZED_CODE)
            ->willReturn($authCode);
        $this->authCodeRepositoryMock->expects($this->once())
            ->method('consumePreAuthorizedCode')
            ->with(self::PRE_AUTHORIZED_CODE)
            ->willReturnCallback(function () use (&$operationOrder): bool {
                $operationOrder[] = 'consume';
                return true;
            });

        $this->accessTokenEntityFactoryMock->expects($this->once())
            ->method('fromData')
            ->willReturn($accessToken);
        $this->accessTokenRepositoryMock->expects($this->once())
            ->method('persistNewAccessToken')
            ->with($accessToken)
            ->willReturnCallback(function () use (&$operationOrder): void {
                $operationOrder[] = 'persist';
            });
        $responseType->expects($this->once())->method('setAccessToken')->with($accessToken);

        $result = $this->sut()->respondToAccessTokenRequest(
            $this->requestMock,
            $responseType,
            new DateInterval('PT5M'),
        );

        $this->assertSame($responseType, $result);
        $this->assertSame(['consume', 'persist'], $operationOrder);
        $this->assertLogged(
            'notice',
            'Pre-authorized code redeemed; access token issued.',
            ['client_id' => self::CLIENT_ID],
        );
        $this->assertSecretsWereNotLogged(self::PRE_AUTHORIZED_CODE, self::TRANSACTION_CODE);
    }


    public function testRejectsReplayBeforeIssuingAnotherAccessToken(): void
    {
        $this->configureRequestParameters(null);
        $this->withNoAuthorizationDetails();
        $authCode = $this->preAuthorizedCode();

        $this->authCodeRepositoryMock->method('findById')->willReturn($authCode);
        $this->authCodeRepositoryMock->expects($this->once())
            ->method('consumePreAuthorizedCode')
            ->with(self::PRE_AUTHORIZED_CODE)
            ->willReturn(false);
        $this->accessTokenEntityFactoryMock->expects($this->never())->method('fromData');
        $this->accessTokenRepositoryMock->expects($this->never())->method('persistNewAccessToken');

        $this->assertTokenRequestRefused('invalid_grant', self::INVALID_CODE_HINT);
        $this->assertLogged(
            'notice',
            'Token request rejected: pre-authorized code was already consumed or is no longer valid.',
        );
        $this->assertSecretsWereNotLogged(self::PRE_AUTHORIZED_CODE);
    }


    public function testRejectsInvalidTransactionCodeWithoutConsumingPreAuthorizedCode(): void
    {
        $submittedTransactionCode = '9999';
        $this->configureRequestParameters($submittedTransactionCode);
        $authCode = $this->preAuthorizedCode(self::TRANSACTION_CODE);

        $this->authCodeRepositoryMock->method('findById')->willReturn($authCode);
        $this->authCodeRepositoryMock->expects($this->never())->method('consumePreAuthorizedCode');
        $this->accessTokenRepositoryMock->expects($this->never())->method('persistNewAccessToken');

        $this->assertTokenRequestRefused('invalid_request', 'Transaction Code is invalid.');
        $this->assertLogged(
            'warning',
            'Transaction code parameter value does not match pre-authorized code transaction code.',
        );
        $this->assertSecretsWereNotLogged(
            self::PRE_AUTHORIZED_CODE,
            self::TRANSACTION_CODE,
            $submittedTransactionCode,
        );
    }


    /**
     * Fail closed: the code is consumed before the token is persisted, and when persistence then fails the
     * grant lets the failure through and makes no attempt to give the code back, so a retry meets a consumed
     * code (the replay test above). The repository sees the lookup and the consumption and nothing else.
     */
    public function testTokenPersistenceFailureLeavesPreAuthorizedCodeConsumed(): void
    {
        $this->configureRequestParameters(null);
        $this->withNoAuthorizationDetails();
        $accessToken = $this->createMock(AccessTokenEntity::class);

        $this->authCodeRepositoryMock->expects($this->once())
            ->method('findById')
            ->with(self::PRE_AUTHORIZED_CODE)
            ->willReturn($this->preAuthorizedCode());
        $this->authCodeRepositoryMock->expects($this->once())
            ->method('consumePreAuthorizedCode')
            ->with(self::PRE_AUTHORIZED_CODE)
            ->willReturn(true);
        $this->authCodeRepositoryMock->expects($this->never())
            ->method($this->logicalNot($this->logicalOr('findById', 'consumePreAuthorizedCode')));
        $this->accessTokenEntityFactoryMock->expects($this->once())
            ->method('fromData')
            ->willReturn($accessToken);
        $this->accessTokenRepositoryMock->expects($this->once())
            ->method('persistNewAccessToken')
            ->with($accessToken)
            ->willThrowException(new RuntimeException('Access-token storage failed.'));

        try {
            $this->sut()->respondToAccessTokenRequest(
                $this->requestMock,
                $this->createMock(ResponseTypeInterface::class),
                new DateInterval('PT5M'),
            );
            $this->fail('The access-token persistence failure must be propagated.');
        } catch (RuntimeException $exception) {
            $this->assertSame('Access-token storage failed.', $exception->getMessage());
        }

        $this->assertSecretsWereNotLogged(self::PRE_AUTHORIZED_CODE);
    }


    /**
     * The grant_type value the token endpoint matches this grant by, the one the openid library's
     * GrantTypesEnum::PreAuthorizedCode carries.
     */
    public function testIdentifiesItselfByThePreAuthorizedCodeGrantType(): void
    {
        $this->assertSame('urn:ietf:params:oauth:grant-type:pre-authorized_code', $this->sut()->getIdentifier());
    }


    /**
     * A pre-authorized code is never requested through the authorization endpoint, so the grant claims no
     * authorization request, without so much as reading it, and is never an OpenID Connect candidate.
     */
    public function testTakesNoPartInAuthorizationRequests(): void
    {
        $this->requestMock->expects($this->never())->method($this->anything());

        $this->assertFalse($this->sut()->canRespondToAuthorizationRequest($this->requestMock));
        $this->assertFalse($this->sut()->isOidcCandidate(new OAuth2AuthorizationRequest()));
    }


    /**
     * The parent's four hooks which carry an authorization request towards a code are closed here with the
     * same server error, the protected auth code issuance included, so that no path through the parent can
     * mint a pre-authorized code.
     */
    #[DataProvider('closedHookProvider')]
    public function testKeepsEveryAuthorizationEndpointHookClosed(Closure $hook): void
    {
        try {
            $hook($this->sut(), $this);

            $this->fail('The hook answered.');
        } catch (OidcServerException $exception) {
            $this->assertServerError($exception, 'Not implemented');
        }
    }


    public static function closedHookProvider(): array
    {
        return [
            'completing an authorization request' => [
                static fn(PreAuthCodeGrant $grant): mixed => $grant->completeAuthorizationRequest(
                    new OAuth2AuthorizationRequest(),
                ),
            ],
            'completing an OpenID Connect authorization request' => [
                static fn(PreAuthCodeGrant $grant): mixed => $grant->completeOidcAuthorizationRequest(
                    new AuthorizationRequest(),
                ),
            ],
            'validating an authorization request with the request rules' => [
                static fn(PreAuthCodeGrant $grant, self $test): mixed => $grant
                    ->validateAuthorizationRequestWithRequestRules($test->requestMock, new ResultBag()),
            ],
            'issuing an OpenID Connect auth code' => [
                static fn(PreAuthCodeGrant $grant, self $test): mixed => (new ReflectionMethod(
                    PreAuthCodeGrant::class,
                    'issueOidcAuthCode',
                ))->invoke(
                    $grant,
                    new DateInterval('PT1M'),
                    $test->createMock(OAuth2ClientEntityInterface::class),
                    self::USER_ID,
                    'openid-credential-offer://',
                    new AuthorizationRequest(),
                ),
            ],
        ];
    }


    #[DataProvider('missingParameterProvider')]
    public function testRefusesATokenRequestWithoutAPreAuthorizedCode(?string $preAuthorizedCode): void
    {
        $this->configureRequestParameters(null, preAuthorizedCode: $preAuthorizedCode);
        $this->authCodeRepositoryMock->expects($this->never())->method('findById');
        $this->authCodeRepositoryMock->expects($this->never())->method('consumePreAuthorizedCode');

        $this->assertTokenRequestRefused('invalid_request', 'Check the `pre-authorized_code` parameter');
        $this->assertLogged('error', 'Empty pre-authorized code ID.');
    }


    public static function missingParameterProvider(): array
    {
        return [
            'not sent' => [null],
            'sent empty' => [''],
        ];
    }


    /**
     * The conditional consumption is what makes the replay guard, and only the module's own repository has
     * it, so the grant refuses to run on any other implementation of the League interface it is typed
     * against rather than issue tokens it could not guard.
     */
    public function testRefusesToRunOnAnAuthCodeRepositoryWhichCannotConsumeACode(): void
    {
        $this->configureRequestParameters(null);
        $this->accessTokenEntityFactoryMock->expects($this->never())->method('fromData');

        try {
            $this->sut($this->createMock(OAuth2AuthCodeRepositoryInterface::class))->respondToAccessTokenRequest(
                $this->requestMock,
                $this->createMock(ResponseTypeInterface::class),
                new DateInterval('PT5M'),
            );

            $this->fail('The token request was answered.');
        } catch (OidcServerException $exception) {
            $this->assertServerError($exception, 'Unexpected auth code repository entity type.');
        }
    }


    /**
     * An unknown code gets the same refusal as a consumed one, so that the answer does not reveal whether
     * the code exists.
     */
    public function testRefusesAPreAuthorizedCodeItDoesNotKnow(): void
    {
        $this->configureRequestParameters(null);
        $this->authCodeRepositoryMock->expects($this->once())
            ->method('findById')
            ->with(self::PRE_AUTHORIZED_CODE)
            ->willReturn(null);
        $this->authCodeRepositoryMock->expects($this->never())->method('consumePreAuthorizedCode');

        $this->assertTokenRequestRefused('invalid_grant', self::INVALID_CODE_HINT);
        $this->assertLogged('notice', 'Token request rejected: pre-authorized code was not found.');
        $this->assertSecretsWereNotLogged(self::PRE_AUTHORIZED_CODE);
    }


    #[DataProvider('notPreAuthorizedProvider')]
    public function testRefusesACodeWhichWasNotPreAuthorized(?FlowTypeEnum $flowType): void
    {
        $this->configureRequestParameters(null);
        $this->authCodeRepositoryMock->method('findById')
            ->willReturn($this->preAuthorizedCode(flowType: $flowType));
        $this->authCodeRepositoryMock->expects($this->never())->method('consumePreAuthorizedCode');

        $this->assertTokenRequestRefused('invalid_grant', 'Pre-authorized code is not pre-authorized.');
        $this->assertLogged('error', 'Pre-authorized code is not pre-authorized.');
    }


    /**
     * The credential issuance flow's own authorization code is the case that matters: a check on the flow
     * family rather than on the exact flow would wave it through.
     */
    public static function notPreAuthorizedProvider(): array
    {
        return [
            'an authorization code of the credential issuance flow' => [FlowTypeEnum::VciAuthorizationCode],
            'a code with no flow recorded' => [null],
        ];
    }


    public function testRefusesAnExpiredPreAuthorizedCode(): void
    {
        $this->configureRequestParameters(null);
        $this->authCodeRepositoryMock->method('findById')
            ->willReturn($this->preAuthorizedCode(expiresAt: '-1 hour'));
        $this->authCodeRepositoryMock->expects($this->never())->method('consumePreAuthorizedCode');

        $this->assertTokenRequestRefused('invalid_grant', 'Pre-authorized code is expired.');
        $this->assertLogged('error', 'Pre-authorized code is expired.');
    }


    public function testRefusesARevokedPreAuthorizedCode(): void
    {
        $this->configureRequestParameters(null);
        $this->authCodeRepositoryMock->method('findById')->willReturn($this->preAuthorizedCode(isRevoked: true));
        $this->authCodeRepositoryMock->expects($this->never())->method('consumePreAuthorizedCode');

        $this->assertTokenRequestRefused('invalid_grant', 'Pre-authorized code is revoked.');
        $this->assertLogged('error', 'Pre-authorized code is revoked.');
    }


    #[DataProvider('missingParameterProvider')]
    public function testRequiresTheTransactionCodeWhenTheCodeCarriesOne(?string $transactionCode): void
    {
        $this->configureRequestParameters($transactionCode);
        $this->authCodeRepositoryMock->method('findById')
            ->willReturn($this->preAuthorizedCode(self::TRANSACTION_CODE));
        $this->authCodeRepositoryMock->expects($this->never())->method('consumePreAuthorizedCode');

        $this->assertTokenRequestRefused('invalid_request', 'Transaction Code is missing.');
        $this->assertLogged('warning', 'Empty transaction code parameter.');
        $this->assertSecretsWereNotLogged(self::PRE_AUTHORIZED_CODE, self::TRANSACTION_CODE);
    }


    public function testDoesNotAskForATransactionCodeWhenTheCodeCarriesNone(): void
    {
        $this->configureRequestParameters(self::TRANSACTION_CODE);
        $this->withNoAuthorizationDetails();
        $this->authCodeRepositoryMock->method('findById')->willReturn($this->preAuthorizedCode());
        $this->authCodeRepositoryMock->method('consumePreAuthorizedCode')->willReturn(true);
        $this->accessTokenEntityFactoryMock->method('fromData')
            ->willReturn($this->createMock(AccessTokenEntity::class));

        $this->sut()->respondToAccessTokenRequest(
            $this->requestMock,
            $this->createMock(ResponseTypeInterface::class),
            new DateInterval('PT5M'),
        );

        $this->assertSame([ParamsEnum::PreAuthorizedCode->value, ParamsEnum::ClientId->value], $this->askedParameters);
    }


    /**
     * The token is made for the code's client and holder, with no scopes yet, expiring after the lifetime
     * given, marked as issued through the pre-authorized code flow, tied to the code, bound to the client id
     * presented and carrying whatever the authorization details rule read from the request. The request is
     * put through that one rule with the token endpoint's method, and the issued token is announced through
     * the emitter with the request it answered.
     */
    #[DataProvider('holderProvider')]
    public function testIssuesTheAccessTokenForTheCodeHolderBoundToTheClientAndTheAuthorizationDetails(
        ?string $holder,
        ?array $authorizationDetails,
    ): void {
        $this->configureRequestParameters(null);
        $this->requestRulesManagerMock->expects($this->once())->method('check')->with(
            $this->identicalTo($this->requestMock),
            [AuthorizationDetailsRule::class],
            $this->isInstanceOf(QueryResponseMode::class),
            [HttpMethodsEnum::POST],
        )->willReturn($this->resultBagWith($authorizationDetails));
        $this->authCodeRepositoryMock->method('findById')->willReturn($this->preAuthorizedCode(holder: $holder));
        $this->authCodeRepositoryMock->method('consumePreAuthorizedCode')->willReturn(true);
        $accessToken = $this->createMock(AccessTokenEntity::class);
        $tokenData = [];
        $this->accessTokenEntityFactoryMock->expects($this->once())->method('fromData')->willReturnCallback(
            function (
                string $id,
                OAuth2ClientEntityInterface $clientEntity,
                array $scopes,
                DateTimeImmutable $expiryDateTime,
                int|string|null $userIdentifier,
                ?string $authCodeId,
                ?array $requestedClaims,
                ?bool $isRevoked,
                ?FlowTypeEnum $flowTypeEnum,
                ?array $authorizationDetails,
                ?string $boundClientId,
                ?string $boundRedirectUri,
                ?string $issuerState,
            ) use (
                &$tokenData,
                $accessToken,
            ): AccessTokenEntity {
                $tokenData = compact(
                    'id',
                    'clientEntity',
                    'scopes',
                    'expiryDateTime',
                    'userIdentifier',
                    'authCodeId',
                    'requestedClaims',
                    'isRevoked',
                    'flowTypeEnum',
                    'authorizationDetails',
                    'boundClientId',
                    'boundRedirectUri',
                    'issuerState',
                );

                return $accessToken;
            },
        );
        $emitter = new EventEmitter();
        $emitted = [];
        $emitter->subscribeTo(
            RequestEvent::ACCESS_TOKEN_ISSUED,
            static function (RequestEvent $event) use (&$emitted): void {
                $emitted[] = $event->getRequest();
            },
        );
        $sut = $this->sut();
        $sut->setEmitter($emitter);

        $sut->respondToAccessTokenRequest(
            $this->requestMock,
            $this->createMock(ResponseTypeInterface::class),
            new DateInterval('PT5M'),
        );

        $this->assertNotSame('', $tokenData['id']);
        $this->assertSame($this->clientMock, $tokenData['clientEntity']);
        $this->assertSame([], $tokenData['scopes']);
        $this->assertEqualsWithDelta(time() + 300, $tokenData['expiryDateTime']->getTimestamp(), 2);
        $this->assertSame($holder, $tokenData['userIdentifier']);
        $this->assertSame(self::PRE_AUTHORIZED_CODE, $tokenData['authCodeId']);
        $this->assertNull($tokenData['requestedClaims']);
        $this->assertFalse($tokenData['isRevoked']);
        $this->assertSame(FlowTypeEnum::VciPreAuthorizedCode, $tokenData['flowTypeEnum']);
        $this->assertSame($authorizationDetails, $tokenData['authorizationDetails']);
        $this->assertSame(self::CLIENT_ID, $tokenData['boundClientId']);
        $this->assertNull($tokenData['boundRedirectUri']);
        $this->assertNull($tokenData['issuerState']);
        $this->assertSame([$this->requestMock], $emitted);
    }


    public static function holderProvider(): array
    {
        return [
            'a code with a holder and authorization details' => [self::USER_ID, self::AUTHORIZATION_DETAILS],
            'a code with neither' => [null, null],
        ];
    }


    /**
     * Nothing in this class calls issueRefreshToken(): respondToAccessTokenRequest() issues no refresh token,
     * and the parent's path which would is overridden above. The override repeats the parent's, so the
     * contract is put on record by reflection: the issuer is asked with the grant's own refresh token
     * lifetime and its attempt limit, and answers for it.
     */
    public function testIssuesARefreshTokenThroughTheIssuerWithItsOwnLifetimeAndAttemptLimit(): void
    {
        $accessToken = $this->createMock(AccessTokenEntity::class);
        $refreshToken = $this->createMock(RefreshTokenEntityInterface::class);
        $refreshTokenTtl = new DateInterval('PT2H');
        $attemptLimit = (new ReflectionClassConstant(
            PreAuthCodeGrant::class,
            'MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS',
        ))->getValue();
        $this->refreshTokenIssuerMock->expects($this->once())->method('issue')->with(
            $this->identicalTo($accessToken),
            $this->identicalTo($refreshTokenTtl),
            'auth-code-id',
            $this->identicalTo($attemptLimit),
        )->willReturn($refreshToken);
        $sut = $this->sut();
        $sut->setRefreshTokenTTL($refreshTokenTtl);

        $this->assertSame($refreshToken, $this->issueRefreshToken($sut, $accessToken, 'auth-code-id'));
    }


    public function testRefusesToIssueARefreshTokenForAnAccessTokenOfAnotherType(): void
    {
        $this->refreshTokenIssuerMock->expects($this->never())->method('issue');

        try {
            $this->issueRefreshToken($this->sut(), $this->createMock(OAuth2AccessTokenEntityInterface::class));

            $this->fail('A refresh token was issued.');
        } catch (OidcServerException $exception) {
            $this->assertServerError($exception, 'Unexpected access token entity type.');
        }
    }


    private function sut(?OAuth2AuthCodeRepositoryInterface $authCodeRepository = null): PreAuthCodeGrant
    {
        return new PreAuthCodeGrant(
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
    }


    private function issueRefreshToken(
        PreAuthCodeGrant $grant,
        OAuth2AccessTokenEntityInterface $accessToken,
        ?string $authCodeId = null,
    ): ?RefreshTokenEntityInterface {
        /** @var ?\SimpleSAML\Module\oidc\Entities\Interfaces\RefreshTokenEntityInterface $refreshToken */
        $refreshToken = (new ReflectionMethod(PreAuthCodeGrant::class, 'issueRefreshToken'))
            ->invoke($grant, $accessToken, $authCodeId);

        return $refreshToken;
    }


    private function preAuthorizedCode(
        ?string $transactionCode = null,
        ?FlowTypeEnum $flowType = FlowTypeEnum::VciPreAuthorizedCode,
        string $expiresAt = '+1 hour',
        bool $isRevoked = false,
        ?string $holder = self::USER_ID,
    ): AuthCodeEntity {
        return new AuthCodeEntity(
            self::PRE_AUTHORIZED_CODE,
            $this->clientMock,
            [],
            new DateTimeImmutable($expiresAt),
            $holder,
            'openid-credential-offer://',
            isRevoked: $isRevoked,
            flowTypeEnum: $flowType,
            txCode: $transactionCode,
        );
    }


    /**
     * Every parameter is read from the request given, over the token endpoint's method only; the parameters
     * asked for are kept for the tests which pin that one was not.
     */
    private function configureRequestParameters(
        ?string $transactionCode,
        ?string $preAuthorizedCode = self::PRE_AUTHORIZED_CODE,
    ): void {
        $this->requestParamsResolverMock->expects($this->never())->method('getAllFromRequest');
        $this->requestParamsResolverMock->method('getAsStringBasedOnAllowedMethods')
            ->willReturnCallback(
                function (
                    string $parameter,
                    ServerRequestInterface $request,
                    array $allowedMethods,
                ) use (
                    $transactionCode,
                    $preAuthorizedCode,
                ): ?string {
                    $this->assertSame($this->requestMock, $request);
                    $this->assertSame([HttpMethodsEnum::POST], $allowedMethods);
                    $this->askedParameters[] = $parameter;

                    return match ($parameter) {
                        ParamsEnum::PreAuthorizedCode->value => $preAuthorizedCode,
                        ParamsEnum::TxCode->value => $transactionCode,
                        ParamsEnum::ClientId->value => self::CLIENT_ID,
                        default => null,
                    };
                },
            );
    }


    private function withNoAuthorizationDetails(): void
    {
        $this->requestRulesManagerMock->method('check')->willReturn(new ResultBag());
    }


    private function resultBagWith(?array $authorizationDetails): ResultBag
    {
        $resultBag = new ResultBag();
        if ($authorizationDetails !== null) {
            $resultBag->add(new Result(AuthorizationDetailsRule::class, $authorizationDetails));
        }

        return $resultBag;
    }


    private function assertTokenRequestRefused(string $errorType, string $hint): void
    {
        try {
            $this->sut()->respondToAccessTokenRequest(
                $this->requestMock,
                $this->createMock(ResponseTypeInterface::class),
                new DateInterval('PT5M'),
            );
        } catch (OidcServerException $exception) {
            $this->assertSame($errorType, $exception->getErrorType());
            $this->assertSame($hint, $exception->getHint());

            return;
        }

        $this->fail('The token request was answered.');
    }


    /**
     * League's server error carries its hint at the end of the message and none in getHint(); the hint is
     * the grant's, the rest of the message League's.
     */
    private function assertServerError(OidcServerException $exception, string $hint): void
    {
        $this->assertSame('server_error', $exception->getErrorType());
        $this->assertStringEndsWith(': ' . $hint, $exception->getMessage());
        $this->assertNull($exception->getHint());
    }


    private function captureLogs(string $level): void
    {
        $this->loggerServiceMock->method($level)->willReturnCallback(
            function (string|Stringable $message, array $context = []) use ($level): void {
                $this->logRecords[] = ['level' => $level, 'message' => (string)$message, 'context' => $context];
            },
        );
    }


    private function assertLogged(string $level, string $message, ?array $context = null): void
    {
        $records = array_values(array_filter(
            $this->logRecords,
            static fn(array $record): bool => $record['level'] === $level && $record['message'] === $message,
        ));

        $this->assertCount(1, $records, sprintf('Expected one %s log line "%s".', $level, $message));
        if ($context !== null) {
            $this->assertSame($context, $records[0]['context']);
        }
    }


    private function assertSecretsWereNotLogged(string ...$secrets): void
    {
        $logs = json_encode($this->logRecords, JSON_THROW_ON_ERROR);
        foreach ($secrets as $secret) {
            $this->assertStringNotContainsString($secret, $logs);
        }
    }
}
