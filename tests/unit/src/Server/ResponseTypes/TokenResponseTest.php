<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\ResponseTypes;

use DateTimeImmutable;
use Exception;
use Laminas\Diactoros\Response;
use League\OAuth2\Server\CryptKey;
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
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Core;
use SimpleSAML\OpenID\Core\Factories\IdTokenFactory;
use SimpleSAML\OpenID\Core\IdToken;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPair;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairBag;

/**
 * @covers \SimpleSAML\Module\oidc\Server\ResponseTypes\TokenResponse
 */
class TokenResponseTest extends TestCase
{
    final public const TOKEN_ID = 'tokenId';
    final public const ISSUER = 'someIssuer';
    final public const CLIENT_ID = 'clientId';
    final public const SUBJECT = 'userId';
    final public const KEY_ID = 'bafd184e90a88107054f4bc05f5e7a76';
    final public const USER_ID_ATTR = 'uid';
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
    protected MockObject $connectSignatureKeyPairBagMock;
    protected MockObject $idTokenFactoryMock;
    protected MockObject $idTokenMock;
    protected MockObject $signatureKeyPairMock;

    /**
     * @throws \PHPUnit\Framework\MockObject\Exception
     * @throws \ReflectionException
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->certFolder = dirname(__DIR__, 5) . '/docker/ssp/';
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

        $this->idTokenBuilder = new IdTokenBuilder(
            new ClaimTranslatorExtractor(self::USER_ID_ATTR, $this->claimSetEntityFactoryStub),
            $this->coreMock,
            $this->moduleConfigMock,
        );

        $this->loggerMock = $this->createMock(LoggerService::class);

        $this->connectSignatureKeyPairBagMock = $this->createMock(SignatureKeyPairBag::class);
        $this->signatureKeyPairMock = $this->createMock(SignatureKeyPair::class);
        $this->signatureKeyPairMock->method('getSignatureAlgorithm')
            ->willReturn(SignatureAlgorithmEnum::RS256);
        $this->connectSignatureKeyPairBagMock->method('getFirstOrFail')
            ->willReturn($this->signatureKeyPairMock);

        $this->moduleConfigMock->method('getConnectSignatureKeyPairBag')
            ->willReturn($this->connectSignatureKeyPairBagMock);

        $this->idTokenMock = $this->createMock(IdToken::class);
    }

    protected function prepareMockedInstance(): TokenResponse
    {
        $tokenResponse = new TokenResponse(
            $this->identityProviderMock,
            $this->idTokenBuilder,
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
