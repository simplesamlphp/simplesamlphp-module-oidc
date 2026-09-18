<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\ResponseTypes;

use DateTimeImmutable;
use Defuse\Crypto\Crypto;
use Defuse\Crypto\Key;
use Exception;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Factories\Entities\ClaimSetEntityFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\Interfaces\IdentityProviderInterface;
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

        $this->accessTokenEntityMock = $this->createMock(AccessTokenEntity::class);
        $this->accessTokenEntityMock->method('getExpiryDateTime')->willReturn($this->expiration);
        $this->accessTokenEntityMock->method('__toString')->willReturn('AccessToken123');
        $this->accessTokenEntityMock->method('toString')->willReturn('AccessToken123');
        $this->accessTokenEntityMock->method('getIdentifier')->willReturn(self::TOKEN_ID);
        $this->accessTokenEntityMock->method('getUserIdentifier')->willReturn(self::SUBJECT);
        $this->accessTokenEntityMock->method('getClient')->willReturn($this->clientEntityMock);

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


    protected function prepareMockedInstance(?IdTokenBuilder $idTokenBuilder = null): TokenResponse
    {
        $idTokenBuilder ??= $this->idTokenBuilder;

        $tokenResponse = new TokenResponse(
            $this->identityProviderMock,
            $idTokenBuilder,
            $this->privateKey,
            $this->loggerMock,
        );

        $tokenResponse->setNonce(null);
        $tokenResponse->setAuthTime(null);
        $tokenResponse->setAcr(null);
        $tokenResponse->setSessionId(null);

        return $tokenResponse;
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
