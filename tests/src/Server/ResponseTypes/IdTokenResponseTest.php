<?php

namespace SimpleSAML\Test\Module\oidc\Server\ResponseTypes;

use DateTimeImmutable;
use Exception;
use Laminas\Diactoros\Response;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Validation\Constraint\IdentifiedBy;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\RelatedTo;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use Lcobucci\JWT\Validation\Validator;
use League\OAuth2\Server\CryptKey;
use OpenIDConnectServer\Repositories\IdentityProviderInterface;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Entity\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entity\ClientEntity;
use SimpleSAML\Module\oidc\Entity\ScopeEntity;
use SimpleSAML\Module\oidc\Entity\UserEntity;
use SimpleSAML\Module\oidc\Server\ResponseTypes\IdTokenResponse;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Services\ConfigurationService;
use SimpleSAML\Module\oidc\Services\IdTokenBuilder;
use SimpleSAML\Module\oidc\Services\JsonWebTokenBuilderService;

/**
 * @covers \SimpleSAML\Module\oidc\Server\ResponseTypes\IdTokenResponse
 */
class IdTokenResponseTest extends TestCase
{
    public const TOKEN_ID = 'tokenId';
    public const ISSUER = 'someIssuer';
    public const CLIENT_ID = 'clientId';
    public const SUBJECT = 'userId';
    public const KEY_ID = 'bafd184e90a88107054f4bc05f5e7a76';
    public const USER_ID_ATTR = 'uid';
    protected string $certFolder;
    protected UserEntity $userEntity;
    protected array $scopes;
    protected \DateTimeImmutable $expiration;
    protected \PHPUnit\Framework\MockObject\MockObject $clientEntityMock;
    protected \PHPUnit\Framework\MockObject\MockObject $accessTokenEntityMock;
    protected \PHPUnit\Framework\MockObject\MockObject $identityProviderMock;
    protected \PHPUnit\Framework\MockObject\MockObject $configurationServiceMock;
    protected \PHPUnit\Framework\MockObject\MockObject $sspConfigurationMock;
    protected CryptKey $privateKey;
    protected IdTokenBuilder $idTokenBuilder;

    protected function setUp(): void
    {
        $this->certFolder = dirname(__DIR__, 4) . '/docker/ssp/';
        $this->userEntity = UserEntity::fromData(self::SUBJECT, [
            'cn'  => ['Homer Simpson'],
            'mail' => ['myEmail@example.com']
        ]);
        $this->scopes = [
            ScopeEntity::fromData('openid'),
            ScopeEntity::fromData('email'),
        ];
        $this->expiration = (new \DateTimeImmutable())->setTimestamp(time() + 3600);

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

        $this->configurationServiceMock = $this->createMock(ConfigurationService::class);
        $this->configurationServiceMock->method('getSigner')->willReturn(new Sha256());
        $this->configurationServiceMock->method('getSimpleSAMLSelfURLHost')->willReturn(self::ISSUER);
        $this->configurationServiceMock->method('getCertPath')
            ->willReturn($this->certFolder . '/oidc_module.crt');
        $this->configurationServiceMock->method('getPrivateKeyPath')
            ->willReturn($this->certFolder . '/oidc_module.key');
        $this->configurationServiceMock
            ->expects($this->atLeast(1))
            ->method('getPrivateKeyPassPhrase');
        $this->sspConfigurationMock = $this->createMock(Configuration::class);
        $this->configurationServiceMock->method('getOpenIDConnectConfiguration')
            ->willReturn($this->sspConfigurationMock);

        $this->privateKey = new CryptKey($this->certFolder . '/oidc_module.key', null, false);

        $this->idTokenBuilder = new IdTokenBuilder(
            new JsonWebTokenBuilderService($this->configurationServiceMock),
            new ClaimTranslatorExtractor(self::USER_ID_ATTR)
        );
    }

    protected function prepareMockedInstance(): IdTokenResponse
    {
        $idTokenResponse = new IdTokenResponse(
            $this->identityProviderMock,
            $this->idTokenBuilder,
            $this->privateKey,
        );

        $idTokenResponse->setNonce(null);
        $idTokenResponse->setAuthTime(null);
        $idTokenResponse->setAcr(null);
        $idTokenResponse->setSessionId(null);

        return $idTokenResponse;
    }

    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            IdTokenResponse::class,
            $this->prepareMockedInstance()
        );
    }

    public function testItCanGenerateResponse(): void
    {
        $this->accessTokenEntityMock->method('getRequestedClaims')->willReturn([]);
        $this->accessTokenEntityMock->method('getScopes')->willReturn($this->scopes);
        $idTokenResponse = $this->prepareMockedInstance();
        $idTokenResponse->setAccessToken($this->accessTokenEntityMock);
        $response = $idTokenResponse->generateHttpResponse(new Response());

        $response->getBody()->rewind();
        $body = $response->getBody()->getContents();
        $this->assertTrue($this->shouldHaveValidIdToken($body));
    }

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
                        ]
                    ],
                    "userinfo" => [
                        "email" => [
                            "essential" => true,
                        ]
                    ]
                ]
            );
        $this->accessTokenEntityMock->method('getScopes')->willReturn(
            [ScopeEntity::fromData('openid'),]
        );
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
            [ScopeEntity::fromData('profile'),]
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
     * @throws Exception
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
                . ' need ' . var_export($expectedResponseFields, true)
            );
        }

        // Check ID token
        $validator = new Validator();
        /** @var Plain $token */
        $token = (new Parser(new JoseEncoder()))->parse($result['id_token']);

        $validator->assert(
            $token,
            new IdentifiedBy(self::TOKEN_ID),
            new IssuedBy(self::ISSUER),
            new PermittedFor(self::CLIENT_ID),
            new RelatedTo(self::SUBJECT),
            new StrictValidAt(SystemClock::fromUTC()),
            new SignedWith(
                new Sha256(),
                InMemory::plainText(file_get_contents($this->certFolder . '/oidc_module.crt'))
            )
        );

        if ($token->headers()->get('kid') !== self::KEY_ID) {
            throw new Exception(
                'Wrong key id. Expected ' . self::KEY_ID . ' was ' . $token->headers()->get('kid')
            );
        }
        $expectedClaimsKeys = array_keys($expectedClaims);
        $expectedClaimsKeys = array_merge(
            ['iss', 'iat', 'jti', 'aud', 'nbf', 'exp', 'sub', 'at_hash'],
            $expectedClaimsKeys
        );
        $claims = array_keys($token->claims()->all());
        if ($claims !== $expectedClaimsKeys) {
            throw new Exception(
                'missing expected claim. Got ' . var_export($claims, true)
                . ' need ' . var_export($expectedClaimsKeys, true)
            );
        }
        foreach ($expectedClaims as $claim => $value) {
            $valFromToken = $token->claims()->get($claim);
            if ($value !== $valFromToken) {
                throw new Exception(
                    'Expected claim value ' . var_export($value, true)
                    . ' got ' . var_export($valFromToken, true)
                );
            }
        }

        $dateWithNoMicroseconds = ['nbf', 'exp', 'iat'];
        foreach ($dateWithNoMicroseconds as $key) {
            /**
             * @var DateTimeImmutable
             */
            $val = $token->claims()->get($key);
            //Get format representing microseconds
            $val = $val->format('u');
            if ($val !== '000000') {
                throw new Exception("Value for '$key' has microseconds. micros '$val'");
            }
        }

        return true;
    }
}
