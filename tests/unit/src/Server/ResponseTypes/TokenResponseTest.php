<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\ResponseTypes;

use DateTimeImmutable;
use Defuse\Crypto\Crypto;
use Defuse\Crypto\Key;
use Exception;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface as OAuth2AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use LogicException;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Factories\Entities\ClaimSetEntityFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\Interfaces\IdentityProviderInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\ResponseTypes\TokenResponse;
use SimpleSAML\Module\oidc\Services\IdTokenBuilder;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Utils\SubjectResolver;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Core;
use SimpleSAML\OpenID\Core\Factories\IdTokenFactory;
use SimpleSAML\OpenID\Core\IdToken;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPair;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairBag;
use Stringable;

/**
 * @covers \SimpleSAML\Module\oidc\Server\ResponseTypes\TokenResponse
 */
#[AllowMockObjectsWithoutExpectations]
class TokenResponseTest extends TestCase
{
    final public const string TOKEN_ID = 'tokenId';

    final public const string ISSUER = 'someIssuer';

    final public const string CLIENT_ID = 'clientId';

    final public const string SUBJECT = 'userId';

    final public const string KEY_ID = 'bafd184e90a88107054f4bc05f5e7a76';

    final public const string USER_ID_ATTR = 'uid';

    /**
     * Two bytes which are not UTF-8, so json_encode() answers false for anything carrying them.
     */
    private const string NOT_UTF8 = "\xB1\x31";

    /**
     * Authorization details in the four shapes the normalization tells apart: an openid_credential entry with a
     * credential_configuration_id, one without, an entry of another type and one without a type at all.
     * AuthorizationDetailsRule, which both VCI grants run, admits the first shape only, so the other three
     * exercise the method's own filtering rather than anything a grant stores today.
     */
    private const array AUTHORIZATION_DETAILS = [
        ['type' => 'openid_credential', 'credential_configuration_id' => 'UniversityDegreeCredential'],
        ['type' => 'openid_credential', 'format' => 'jwt_vc_json'],
        ['type' => 'payment_initiation', 'credential_configuration_id' => 'UniversityDegreeCredential'],
        ['format' => 'dc+sd-jwt'],
    ];

    /**
     * What the token response makes of AUTHORIZATION_DETAILS: only the openid_credential entries, the one with a
     * credential_configuration_id gaining credential_identifiers naming it, the other passed through as it was.
     */
    private const array NORMALIZED_AUTHORIZATION_DETAILS = [
        [
            'type' => 'openid_credential',
            'credential_configuration_id' => 'UniversityDegreeCredential',
            'credential_identifiers' => ['UniversityDegreeCredential'],
        ],
        ['type' => 'openid_credential', 'format' => 'jwt_vc_json'],
    ];


    protected string $certFolder;

    protected UserEntity $userEntity;

    protected array $scopes;

    protected DateTimeImmutable $expiration;

    protected MockObject $clientEntityMock;

    protected MockObject $accessTokenEntityMock;

    protected MockObject $identityProviderMock;

    protected MockObject $moduleConfigMock;

    protected MockObject $sspConfigurationMock;

    protected CryptKey $privateKey;

    protected IdTokenBuilder $idTokenBuilder;

    protected Stub $claimSetEntityFactoryStub;

    protected MockObject $loggerMock;

    protected MockObject $coreMock;

    protected MockObject $protocolSignatureKeyPairBagMock;

    protected MockObject $idTokenFactoryMock;

    protected MockObject $idTokenMock;

    protected MockObject $signatureKeyPairMock;

    protected Key $encryptionKey;

    /**
     * Every debug record the logger received, as [message, context] pairs, once captureDebugLogs() is on.
     *
     * @var list<array{0: string, 1: array}>
     */
    private array $debugLogs = [];


    /**
     * @throws \PHPUnit\Framework\MockObject\Exception
     * @throws \ReflectionException
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->certFolder = dirname(__DIR__, 4) . '/cert/';
        $createdUpdatedAt = new DateTimeImmutable();
        $this->userEntity = new UserEntity(
            self::SUBJECT,
            $createdUpdatedAt,
            $createdUpdatedAt,
            ['cn'  => ['Homer Simpson'], 'mail' => ['myEmail@example.com'],],
        );
        $this->scopes = [
            new ScopeEntity('openid'),
            new ScopeEntity('email'),
        ];
        $this->expiration = (new DateTimeImmutable())->setTimestamp(time() + 3600);

        $this->clientEntityMock = $this->createMock(ClientEntity::class);
        $this->clientEntityMock->method('getIdentifier')->willReturn(self::CLIENT_ID);

        $this->accessTokenEntityMock = $this->createAccessTokenMock();

        $this->identityProviderMock = $this->createMock(IdentityProviderInterface::class);
        $this->identityProviderMock->method('getUserEntityByIdentifier')
            ->with(self::SUBJECT)
            ->willReturn($this->userEntity);

        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getIssuer')->willReturn(self::ISSUER);
        $this->sspConfigurationMock = $this->createMock(Configuration::class);
        $this->moduleConfigMock->method('config')
            ->willReturn($this->sspConfigurationMock);

        $this->privateKey = new CryptKey($this->certFolder . '/oidc_module.key', null, false);

        $this->claimSetEntityFactoryStub = $this->createStub(ClaimSetEntityFactory::class);

        $this->idTokenFactoryMock = $this->createMock(IdTokenFactory::class);

        $this->coreMock = $this->createMock(Core::class);
        $this->coreMock->method('idTokenFactory')->willReturn($this->idTokenFactoryMock);

        $this->loggerMock = $this->createMock(LoggerService::class);

        $claimTranslatorExtractor = new ClaimTranslatorExtractor(
            [self::USER_ID_ATTR],
            $this->claimSetEntityFactoryStub,
        );
        $this->idTokenBuilder = new IdTokenBuilder(
            $claimTranslatorExtractor,
            $this->coreMock,
            $this->moduleConfigMock,
            new SubjectResolver($claimTranslatorExtractor, $this->loggerMock),
        );

        $this->protocolSignatureKeyPairBagMock = $this->createMock(SignatureKeyPairBag::class);
        $this->signatureKeyPairMock = $this->createMock(SignatureKeyPair::class);
        $this->signatureKeyPairMock->method('getSignatureAlgorithm')
            ->willReturn(SignatureAlgorithmEnum::RS256);
        $this->protocolSignatureKeyPairBagMock->method('getFirstOrFail')
            ->willReturn($this->signatureKeyPairMock);

        $this->moduleConfigMock->method('getProtocolSignatureKeyPairBag')
            ->willReturn($this->protocolSignatureKeyPairBagMock);

        $this->idTokenMock = $this->createMock(IdToken::class);

        $this->encryptionKey = Key::createNewRandomKey();
    }


    /**
     * The access token every test starts from. The user identifier is a parameter because a stub configured
     * here cannot be re-configured by a test (the first configured stub keeps answering), and two tests need
     * the token to name no user.
     */
    protected function createAccessTokenMock(?string $userIdentifier = self::SUBJECT): AccessTokenEntity&MockObject
    {
        $accessToken = $this->createMock(AccessTokenEntity::class);
        $accessToken->method('getExpiryDateTime')->willReturn($this->expiration);
        $accessToken->method('__toString')->willReturn('AccessToken123');
        $accessToken->method('toString')->willReturn('AccessToken123');
        $accessToken->method('getIdentifier')->willReturn(self::TOKEN_ID);
        $accessToken->method('getUserIdentifier')->willReturn($userIdentifier);
        $accessToken->method('getClient')->willReturn($this->clientEntityMock);

        return $accessToken;
    }


    protected function prepareMockedInstance(
        ?IdTokenBuilder $idTokenBuilder = null,
        ?IdentityProviderInterface $identityProvider = null,
    ): TokenResponse {
        $tokenResponse = new TokenResponse(
            $identityProvider ?? $this->identityProviderMock,
            $idTokenBuilder ?? $this->idTokenBuilder,
            $this->privateKey,
            $this->loggerMock,
        );

        $tokenResponse->setNonce(null);
        $tokenResponse->setAuthTime(null);
        $tokenResponse->setAcr(null);
        $tokenResponse->setSessionId(null);

        return $tokenResponse;
    }


    /**
     * The two protected hooks made callable, for the guard each carries of its own. Through generateHttpResponse()
     * neither guard can fire: it checks the entity type before calling getExtraParams(), and getExtraParams()
     * reads the authorization details before calling prepareVciAuthorizationDetailsExtraParam().
     */
    protected function prepareExposedInstance(): TokenResponse
    {
        return new class (
            $this->identityProviderMock,
            $this->idTokenBuilder,
            $this->privateKey,
            $this->loggerMock,
        ) extends TokenResponse {
            public function exposedGetExtraParams(OAuth2AccessTokenEntityInterface $accessToken): array
            {
                return $this->getExtraParams($accessToken);
            }


            public function exposedPrepareVciAuthorizationDetailsExtraParam(AccessTokenEntity $accessToken): array
            {
                return $this->prepareVciAuthorizationDetailsExtraParam($accessToken);
            }
        };
    }


    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            TokenResponse::class,
            $this->prepareMockedInstance(),
        );
    }


    /**
     * @throws \Exception
     */
    public function testItCanGenerateResponse(): void
    {
        $this->accessTokenEntityMock->method('getRequestedClaims')->willReturn([]);
        $this->accessTokenEntityMock->method('getScopes')->willReturn($this->scopes);
        $this->idTokenFactoryMock->method('fromData')
            ->willReturn($this->idTokenMock);
        $this->idTokenMock->expects($this->once())
            ->method('getToken')
            ->willReturn('token');
        $idTokenResponse = $this->prepareMockedInstance();
        $idTokenResponse->setAccessToken($this->accessTokenEntityMock);
        $response = $idTokenResponse->generateHttpResponse(new Response());

        $response->getBody()->rewind();
        $body = $response->getBody()->getContents();
        $this->assertTrue($this->shouldHaveValidIdToken($body));
    }


    /**
     * @throws \Exception
     */
    public function testItCanGenerateResponseWithIndividualRequestedClaims(): void
    {
        $idTokenResponse = $this->prepareMockedInstance();
        $this->accessTokenEntityMock
            ->method('getRequestedClaims')
            ->willReturn(
                [
                    "id_token" => [
                        "name" => [
                            "essential" => true,
                        ],
                    ],
                    "userinfo" => [
                        "email" => [
                            "essential" => true,
                        ],
                    ],
                ],
            );
        $this->accessTokenEntityMock->method('getScopes')->willReturn(
            [new ScopeEntity('openid')],
        );
        $this->idTokenFactoryMock->method('fromData')
            ->willReturn($this->idTokenMock);
        $this->idTokenMock->expects($this->once())
            ->method('getToken')
            ->willReturn('token');
        $idTokenResponse->setAccessToken($this->accessTokenEntityMock);
        $response = $idTokenResponse->generateHttpResponse(new Response());

        $response->getBody()->rewind();
        $body = $response->getBody()->getContents();
        $this->assertTrue($this->shouldHaveValidIdToken($body, ['name' => 'Homer Simpson']));
    }


    /**
     * When the client is configured to release user claims in the ID Token (admin-only
     * `add_claims_to_id_token`), the ID Token is built with $addClaimsFromScopes = true, so the scope-derived
     * user claims end up in the ID Token (in addition to the UserInfo endpoint).
     *
     * @throws \Exception
     */
    public function testReleasesUserClaimsInIdTokenWhenClientConfiguredTo(): void
    {
        $this->clientEntityMock->method('getAddClaimsToIdToken')->willReturn(true);
        $this->accessTokenEntityMock->method('getRequestedClaims')->willReturn([]);
        $this->accessTokenEntityMock->method('getScopes')->willReturn($this->scopes);

        $idTokenBuilderMock = $this->createMock(IdTokenBuilder::class);
        $idTokenBuilderMock->expects($this->once())
            ->method('buildFor')
            ->with(
                $this->anything(),
                $this->anything(),
                true, // $addClaimsFromScopes
                $this->anything(),
                $this->anything(),
                $this->anything(),
                $this->anything(),
                $this->anything(),
            )
            ->willReturn($this->idTokenMock);
        $this->idTokenMock->method('getToken')->willReturn('token');

        $idTokenResponse = $this->prepareMockedInstance($idTokenBuilderMock);
        $idTokenResponse->setAccessToken($this->accessTokenEntityMock);
        $idTokenResponse->generateHttpResponse(new Response());
    }


    /**
     * By default (client not configured to release claims in the ID Token), the ID Token is built with
     * $addClaimsFromScopes = false, so scope-derived user claims remain available only at the UserInfo endpoint.
     *
     * @throws \Exception
     */
    public function testDoesNotReleaseUserClaimsInIdTokenByDefault(): void
    {
        $this->clientEntityMock->method('getAddClaimsToIdToken')->willReturn(false);
        $this->accessTokenEntityMock->method('getRequestedClaims')->willReturn([]);
        $this->accessTokenEntityMock->method('getScopes')->willReturn($this->scopes);

        $idTokenBuilderMock = $this->createMock(IdTokenBuilder::class);
        $idTokenBuilderMock->expects($this->once())
            ->method('buildFor')
            ->with(
                $this->anything(),
                $this->anything(),
                false, // $addClaimsFromScopes
                $this->anything(),
                $this->anything(),
                $this->anything(),
                $this->anything(),
                $this->anything(),
            )
            ->willReturn($this->idTokenMock);
        $this->idTokenMock->method('getToken')->willReturn('token');

        $idTokenResponse = $this->prepareMockedInstance($idTokenBuilderMock);
        $idTokenResponse->setAccessToken($this->accessTokenEntityMock);
        $idTokenResponse->generateHttpResponse(new Response());
    }


    public function testNoExtraParamsForNonOidcRequest(): void
    {
        $this->accessTokenEntityMock->method('getRequestedClaims')->willReturn([]);
        $this->accessTokenEntityMock->method('getScopes')->willReturn(
            [new ScopeEntity('profile')],
        );
        $idTokenResponse = $this->prepareMockedInstance();
        $idTokenResponse->setAccessToken($this->accessTokenEntityMock);
        $response = $idTokenResponse->generateHttpResponse(new Response());

        $response->getBody()->rewind();
        $body = $response->getBody()->getContents();
        $this->expectException(Exception::class);
        $this->shouldHaveValidIdToken($body);
    }


    /**
     * The response type only knows how to serialize the module's own access token entity (its subject, flow
     * type and authorization details are not part of League's interface), so any other implementation is
     * refused before a byte is written.
     */
    public function testRefusesAnAccessTokenWhichIsNotTheModulesEntity(): void
    {
        $tokenResponse = $this->prepareMockedInstance();
        $tokenResponse->setAccessToken($this->createMock(OAuth2AccessTokenEntityInterface::class));

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('AccessToken must be ' . AccessTokenEntity::class);

        $tokenResponse->generateHttpResponse(new Response());
    }


    /**
     * The same guard on the getExtraParams() hook, which League's BearerTokenResponse calls with whatever entity
     * it holds; generateHttpResponse() above refuses first, so only a direct call can reach this one.
     */
    public function testTheExtraParamsHookRefusesAnAccessTokenWhichIsNotTheModulesEntity(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('AccessToken must be ' . AccessTokenEntity::class);

        $this->prepareExposedInstance()->exposedGetExtraParams(
            $this->createMock(OAuth2AccessTokenEntityInterface::class),
        );
    }


    /**
     * The refresh token payload is JSON before it is encrypted; a subject which json_encode() cannot represent
     * fails the whole response rather than issuing a refresh token which can never be decoded.
     */
    public function testRefusesToEncodeARefreshTokenPayloadWhichIsNotUtf8(): void
    {
        $this->accessTokenEntityMock->method('getScopes')->willReturn([new ScopeEntity('profile')]);
        $this->accessTokenEntityMock->method('getSubject')->willReturn(self::NOT_UTF8);

        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('Error encountered JSON encoding the refresh token payload');

        $this->generateResponseWithRefreshToken();
    }


    /**
     * The same for the response body: an ID Token which json_encode() cannot represent fails the response.
     */
    public function testRefusesToEncodeAResponseWhichIsNotUtf8(): void
    {
        $this->accessTokenEntityMock->method('getRequestedClaims')->willReturn([]);
        $this->accessTokenEntityMock->method('getScopes')->willReturn($this->scopes);
        $this->idTokenFactoryMock->method('fromData')->willReturn($this->idTokenMock);
        $this->idTokenMock->method('getToken')->willReturn(self::NOT_UTF8);

        $tokenResponse = $this->prepareMockedInstance();
        $tokenResponse->setAccessToken($this->accessTokenEntityMock);

        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('Error encountered JSON encoding response parameters');

        $tokenResponse->generateHttpResponse(new Response());
    }


    /**
     * An ID Token needs an End-User; an openid request whose access token names none is refused as
     * access_denied rather than answered with an ID Token for nobody.
     */
    #[DataProvider('missingUserIdentifierProvider')]
    public function testDeniesAccessWhenTheAccessTokenNamesNoUser(?string $userIdentifier): void
    {
        $accessToken = $this->createAccessTokenMock($userIdentifier);
        $accessToken->method('getScopes')->willReturn($this->scopes);
        $this->identityProviderMock->expects($this->never())->method('getUserEntityByIdentifier');

        $tokenResponse = $this->prepareMockedInstance();
        $tokenResponse->setAccessToken($accessToken);

        $this->assertAccessDenied($tokenResponse, 'No user identifier present in AccessToken.');
    }


    public static function missingUserIdentifierProvider(): array
    {
        return [
            'null' => [null],
            'empty' => [''],
        ];
    }


    /**
     * The same when the identity provider no longer knows the user the access token names.
     */
    public function testDeniesAccessWhenTheUserCannotBeFound(): void
    {
        $this->accessTokenEntityMock->method('getScopes')->willReturn($this->scopes);
        $identityProvider = $this->createMock(IdentityProviderInterface::class);
        $identityProvider->expects($this->once())
            ->method('getUserEntityByIdentifier')
            ->with(self::SUBJECT)
            ->willReturn(null);

        $tokenResponse = $this->prepareMockedInstance(identityProvider: $identityProvider);
        $tokenResponse->setAccessToken($this->accessTokenEntityMock);

        $this->assertAccessDenied($tokenResponse, 'No user available for provided user identifier.');
    }


    /**
     * In a VCI flow the token response echoes the authorization details the access token carries, keeping the
     * openid_credential entries only and naming the credential_configuration_id, where an entry has one, as its
     * credential_identifiers. Both VCI flows qualify; the two debug records show what went in and what came out.
     */
    #[DataProvider('vciFlowProvider')]
    public function testCarriesTheNormalizedAuthorizationDetailsInAVciFlow(FlowTypeEnum $flowType): void
    {
        $this->accessTokenEntityMock->method('getScopes')->willReturn([new ScopeEntity('profile')]);
        $this->accessTokenEntityMock->method('getFlowTypeEnum')->willReturn($flowType);
        $this->accessTokenEntityMock->method('getAuthorizationDetails')->willReturn(self::AUTHORIZATION_DETAILS);
        $this->captureDebugLogs();

        $result = $this->generateResponse();

        $this->assertSame(self::NORMALIZED_AUTHORIZATION_DETAILS, $result['authorization_details']);
        $this->assertArrayNotHasKey('id_token', $result);
        $this->assertSame('AccessToken123', $result['access_token']);
        $this->assertSame(
            [
                [
                    'TokenResponse::prepareAuthorizationDetailsExtraParam',
                    ['accessTokenAuthorizationDetails' => self::AUTHORIZATION_DETAILS],
                ],
                [
                    'TokenResponse::prepareAuthorizationDetailsExtraParam. Summarized authorization details: ',
                    ['authorizationDetails' => self::NORMALIZED_AUTHORIZATION_DETAILS],
                ],
            ],
            $this->debugLogs,
        );
    }


    public static function vciFlowProvider(): array
    {
        return [
            'authorization code' => [FlowTypeEnum::VciAuthorizationCode],
            'pre-authorized code' => [FlowTypeEnum::VciPreAuthorizedCode],
        ];
    }


    /**
     * The ID Token and the authorization details are independent additions: a VCI flow whose scopes include
     * openid gets both.
     */
    public function testCarriesBothTheIdTokenAndTheAuthorizationDetailsWhenTheVciFlowRequestedOpenid(): void
    {
        $this->accessTokenEntityMock->method('getRequestedClaims')->willReturn([]);
        $this->accessTokenEntityMock->method('getScopes')->willReturn($this->scopes);
        $this->accessTokenEntityMock->method('getFlowTypeEnum')->willReturn(FlowTypeEnum::VciAuthorizationCode);
        $this->accessTokenEntityMock->method('getAuthorizationDetails')->willReturn(self::AUTHORIZATION_DETAILS);
        $this->idTokenFactoryMock->method('fromData')->willReturn($this->idTokenMock);
        $this->idTokenMock->method('getToken')->willReturn('token');

        $result = $this->generateResponse();

        $this->assertSame('token', $result['id_token']);
        $this->assertSame(self::NORMALIZED_AUTHORIZATION_DETAILS, $result['authorization_details']);
    }


    /**
     * Outside a VCI flow the authorization details stay off the wire even when the access token carries some,
     * and a VCI flow without any carries none; neither case logs.
     */
    #[DataProvider('noAuthorizationDetailsProvider')]
    public function testLeavesTheAuthorizationDetailsOutUnlessTheFlowIsVci(
        ?FlowTypeEnum $flowType,
        ?array $authorizationDetails,
    ): void {
        $this->accessTokenEntityMock->method('getScopes')->willReturn([new ScopeEntity('profile')]);
        $this->accessTokenEntityMock->method('getFlowTypeEnum')->willReturn($flowType);
        $this->accessTokenEntityMock->method('getAuthorizationDetails')->willReturn($authorizationDetails);
        $this->loggerMock->expects($this->never())->method('debug');

        $result = $this->generateResponse();

        $this->assertArrayNotHasKey('authorization_details', $result);
        $this->assertSame('AccessToken123', $result['access_token']);
    }


    /**
     * The refresh token flow is the case which is neither VCI nor an OIDC flow to FlowTypeEnum::isOidcFlow(), so
     * a check written as "not OIDC" would let it through where the authorization code flow passes.
     */
    public static function noAuthorizationDetailsProvider(): array
    {
        return [
            'no flow type' => [null, self::AUTHORIZATION_DETAILS],
            'OIDC authorization code flow' => [FlowTypeEnum::OidcAuthorizationCode, self::AUTHORIZATION_DETAILS],
            'OIDC refresh token flow' => [FlowTypeEnum::OidcRefreshToken, self::AUTHORIZATION_DETAILS],
            'VCI flow without details' => [FlowTypeEnum::VciAuthorizationCode, null],
        ];
    }


    /**
     * Authorization details without a single openid_credential entry normalize to an empty list, and
     * getExtraParams() passes its additions through array_filter(), so the response carries no
     * authorization_details key at all rather than an empty array.
     */
    public function testLeavesTheAuthorizationDetailsOutWhenNoneNamesAnOpenidCredential(): void
    {
        $this->accessTokenEntityMock->method('getScopes')->willReturn([new ScopeEntity('profile')]);
        $this->accessTokenEntityMock->method('getFlowTypeEnum')->willReturn(FlowTypeEnum::VciAuthorizationCode);
        $this->accessTokenEntityMock->method('getAuthorizationDetails')
            ->willReturn([['type' => 'payment_initiation']]);
        $this->captureDebugLogs();

        $result = $this->generateResponse();

        $this->assertArrayNotHasKey('authorization_details', $result);
        $this->assertSame(
            [
                [
                    'TokenResponse::prepareAuthorizationDetailsExtraParam',
                    ['accessTokenAuthorizationDetails' => [['type' => 'payment_initiation']]],
                ],
                [
                    'TokenResponse::prepareAuthorizationDetailsExtraParam. Summarized authorization details: ',
                    ['authorizationDetails' => []],
                ],
            ],
            $this->debugLogs,
        );
    }


    /**
     * The normalizing hook reads the authorization details itself and answers an empty list without any;
     * getExtraParams() never calls it then, so only a direct call reaches this answer.
     */
    public function testTheAuthorizationDetailsHookAnswersEmptyWithoutDetails(): void
    {
        $this->accessTokenEntityMock->method('getAuthorizationDetails')->willReturn(null);
        $this->captureDebugLogs();

        $this->assertSame(
            [],
            $this->prepareExposedInstance()->exposedPrepareVciAuthorizationDetailsExtraParam(
                $this->accessTokenEntityMock,
            ),
        );
        $this->assertSame(
            [
                [
                    'TokenResponse::prepareAuthorizationDetailsExtraParam',
                    ['accessTokenAuthorizationDetails' => null],
                ],
            ],
            $this->debugLogs,
        );
    }


    /**
     * The refresh token payload is league's (client, ids, scopes, internal user id, expiry) plus the subject the
     * access token was minted with, so that RefreshTokenGrant can carry it into the refreshed tokens and the
     * introspection endpoint can report it. It is the one field league's BearerTokenResponse does not write, and
     * the reason the method is overridden at all.
     *
     * @throws \Exception
     */
    #[DataProvider('carriedSubjectProvider')]
    public function testRefreshTokenPayloadCarriesTheAccessTokensSubject(string $subject): void
    {
        $this->accessTokenEntityMock->method('getRequestedClaims')->willReturn([]);
        $this->accessTokenEntityMock->method('getScopes')->willReturn($this->scopes);
        $this->accessTokenEntityMock->method('getSubject')->willReturn($subject);
        $this->idTokenFactoryMock->method('fromData')->willReturn($this->idTokenMock);
        $this->idTokenMock->method('getToken')->willReturn('token');

        $payload = $this->refreshTokenPayloadOf($this->generateResponseWithRefreshToken());

        $this->assertSame(
            [
                'client_id' => self::CLIENT_ID,
                'refresh_token_id' => 'refresh-token-id',
                'access_token_id' => self::TOKEN_ID,
                'scopes' => ['openid', 'email'],
                'user_id' => self::SUBJECT,
                'expire_time' => $this->expiration->getTimestamp(),
                'sub' => $subject,
            ],
            $payload,
        );
    }


    public static function carriedSubjectProvider(): array
    {
        return [
            'a subject' => ['resolved-subject'],
            'the falsy but valid subject "0"' => ['0'],
        ];
    }


    /**
     * An access token built without a subject leaves the field out rather than writing a null the grant would
     * have to tell apart from a legacy payload anyway.
     */
    public function testRefreshTokenPayloadLeavesTheSubjectOutWhenTheAccessTokenCarriesNone(): void
    {
        $this->accessTokenEntityMock->method('getRequestedClaims')->willReturn([]);
        $this->accessTokenEntityMock->method('getScopes')->willReturn($this->scopes);
        $this->accessTokenEntityMock->method('getSubject')->willReturn(null);
        $this->idTokenFactoryMock->method('fromData')->willReturn($this->idTokenMock);
        $this->idTokenMock->method('getToken')->willReturn('token');

        $payload = $this->refreshTokenPayloadOf($this->generateResponseWithRefreshToken());

        $this->assertArrayNotHasKey('sub', $payload);
        $this->assertSame(self::SUBJECT, $payload['user_id']);
    }


    public function testResponseCarriesNoRefreshTokenUnlessOneWasSet(): void
    {
        $this->accessTokenEntityMock->method('getRequestedClaims')->willReturn([]);
        $this->accessTokenEntityMock->method('getScopes')->willReturn($this->scopes);
        $this->idTokenFactoryMock->method('fromData')->willReturn($this->idTokenMock);
        $this->idTokenMock->method('getToken')->willReturn('token');

        $tokenResponse = $this->prepareMockedInstance();
        $tokenResponse->setAccessToken($this->accessTokenEntityMock);
        $response = $tokenResponse->generateHttpResponse(new Response());

        $response->getBody()->rewind();
        $result = json_decode($response->getBody()->getContents(), true, 512, JSON_THROW_ON_ERROR);

        $this->assertArrayNotHasKey('refresh_token', $result);
        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('no-store', $response->getHeaderLine('cache-control'));
        $this->assertSame('no-cache', $response->getHeaderLine('pragma'));
        $this->assertSame('Bearer', $result['token_type']);
        $this->assertSame('AccessToken123', $result['access_token']);
    }


    /**
     * The decoded body of a response for the shared access token, without a refresh token.
     *
     * @throws \JsonException
     */
    protected function generateResponse(): array
    {
        $tokenResponse = $this->prepareMockedInstance();
        $tokenResponse->setAccessToken($this->accessTokenEntityMock);
        $response = $tokenResponse->generateHttpResponse(new Response());

        $response->getBody()->rewind();

        return json_decode($response->getBody()->getContents(), true, 512, JSON_THROW_ON_ERROR);
    }


    protected function generateResponseWithRefreshToken(): array
    {
        $refreshToken = $this->createMock(RefreshTokenEntityInterface::class);
        $refreshToken->method('getIdentifier')->willReturn('refresh-token-id');
        $refreshToken->method('getExpiryDateTime')->willReturn($this->expiration);

        $tokenResponse = $this->prepareMockedInstance();
        $tokenResponse->setEncryptionKey($this->encryptionKey);
        $tokenResponse->setAccessToken($this->accessTokenEntityMock);
        $tokenResponse->setRefreshToken($refreshToken);
        $response = $tokenResponse->generateHttpResponse(new Response());

        $response->getBody()->rewind();

        return json_decode($response->getBody()->getContents(), true, 512, JSON_THROW_ON_ERROR);
    }


    /**
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     * @throws \Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException
     * @throws \JsonException
     */
    protected function refreshTokenPayloadOf(array $result): array
    {
        $this->assertIsString($result['refresh_token'] ?? null);

        $payload = Crypto::decrypt($result['refresh_token'], $this->encryptionKey);

        return json_decode($payload, true, 512, JSON_THROW_ON_ERROR);
    }


    private function assertAccessDenied(TokenResponse $tokenResponse, string $hint): void
    {
        try {
            $tokenResponse->generateHttpResponse(new Response());
        } catch (OidcServerException $exception) {
            $this->assertSame('access_denied', $exception->getErrorType());
            $this->assertSame($hint, $exception->getHint());

            return;
        }

        $this->fail('The token response was generated.');
    }


    private function captureDebugLogs(): void
    {
        $this->loggerMock->method('debug')->willReturnCallback(
            function (string|Stringable $message, array $context = []): void {
                $this->debugLogs[] = [(string)$message, $context];
            },
        );
    }


    /**
     * @throws \Exception
     */
    protected function shouldHaveValidIdToken(string $body, $expectedClaims = []): bool
    {
        // Check response format
        $result = json_decode($body, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception('Response not json ' . json_last_error_msg());
        }
        $expectedResponseFields = ['id_token', 'expires_in', 'token_type', 'access_token'];
        $responseKeys = array_intersect_key(array_flip($expectedResponseFields), $result);
        if ($responseKeys !== array_flip($expectedResponseFields)) {
            throw new Exception(
                'missing expected keys. Got ' . var_export(array_keys($result), true)
                . ' need ' . var_export($expectedResponseFields, true),
            );
        }

        return true;
    }
}
