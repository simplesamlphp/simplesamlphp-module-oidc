<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Server\Validators;

use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\StreamFactory;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface as OAuth2AccessTokenRepositoryInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\Validators\BearerTokenValidator;

use function chmod;

/**
 * @covers \SimpleSAML\Module\oidc\Server\Validators\BearerTokenValidator
 *
 * @backupGlobals enabled
 */
class BearerTokenValidatorTest extends TestCase
{
    protected BearerTokenValidator $bearerTokenValidator;
    protected static string $privateKeyPath;
    protected static CryptKey $privateCryptKey;
    protected static ?string $privateKey = null;
    protected static string $publicKey;
    protected static CryptKey $publicCryptKey;
    protected static string $publicKeyPath;
    protected OAuth2AccessTokenRepositoryInterface $accessTokenRepositoryStub;
    protected static array $accessTokenState;
    protected static AccessTokenEntity $accessTokenEntity;
    protected static string $accessToken;
    protected static ClientEntityInterface $clientEntity;
    protected ServerRequestInterface $serverRequest;

    /**
     * @throws \Exception
     */
    public function setUp(): void
    {
        $this->accessTokenRepositoryStub = $this->createStub(AccessTokenRepository::class);
        $this->serverRequest = new ServerRequest();
        $this->bearerTokenValidator = new BearerTokenValidator($this->accessTokenRepositoryStub, self::$publicCryptKey);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public static function setUpBeforeClass(): void
    {
        // To make lib/SimpleSAML/Utils/HTTP::getSelfURL() work...
        global $_SERVER;
        $_SERVER['REQUEST_URI'] = '';

        $tempDir = sys_get_temp_dir();

        // Plant certdir config for JsonWebTokenBuilderService (since we don't inject it)
        $config = [
            'certdir' => $tempDir,
        ];
        Configuration::loadFromArray($config, '', 'simplesaml');

        self::$publicKeyPath = $tempDir . '/oidc_module.crt';
        self::$privateKeyPath = $tempDir . '/oidc_module.key';

        $pkGenerate = openssl_pkey_new([
                                           'private_key_bits' => 2048,
                                           'private_key_type' => OPENSSL_KEYTYPE_RSA,
                                       ]);

        // get the private key
        openssl_pkey_export($pkGenerate, self::$privateKey);

        // get the public key
        self::$publicKey = openssl_pkey_get_details($pkGenerate)['key'];

        file_put_contents(self::$publicKeyPath, self::$publicKey);
        file_put_contents(self::$privateKeyPath, self::$privateKey);
        chmod(self::$publicKeyPath, 0600);
        chmod(self::$privateKeyPath, 0600);

        self::$publicCryptKey = new CryptKey(self::$publicKeyPath);
        self::$privateCryptKey = new CryptKey(self::$privateKeyPath);

        self::$clientEntity = ClientEntity::fromData(
            'client1123',
            'secret1',
            'name1',
            'desc1',
            ['redirect-uri'],
            ['openid'],
            true,
        );

        self::$accessTokenState = [
            'id' => 'accessToken123',
            'scopes' => '{"openid":"openid","profile":"profile"}',
            'expires_at' => date('Y-m-d H:i:s', time() + 60),
            'user_id' => 'user123',
            'client' => self::$clientEntity,
            'is_revoked' => false,
            'auth_code_id' => 'authCode123',
        ];

        self::$accessTokenEntity = AccessTokenEntity::fromState(self::$accessTokenState);
        self::$accessTokenEntity->setPrivateKey(self::$privateCryptKey);

        self::$accessToken = (string) self::$accessTokenEntity;
    }

    /**
     * @return void
     */
    public static function tearDownAfterClass(): void
    {
        unlink(self::$publicKeyPath);
        unlink(self::$privateKeyPath);
    }

    public function testValidatorThrowsForNonExistentAccessToken()
    {
        $this->expectException(OidcServerException::class);

        $this->bearerTokenValidator->validateAuthorization($this->serverRequest);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testValidatesForAuthorizationHeader()
    {
        $serverRequest = $this->serverRequest->withAddedHeader('Authorization', 'Bearer ' . self::$accessToken);

        $validatedServerRequest = $this->bearerTokenValidator->validateAuthorization($serverRequest);

        $this->assertSame(
            self::$accessTokenState['id'],
            $validatedServerRequest->getAttribute('oauth_access_token_id'),
        );
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testValidatesForPostBodyParam()
    {
        $bodyArray = ['access_token' => self::$accessToken];
        $tempStream = (new StreamFactory())->createStream(http_build_query($bodyArray));

        $serverRequest = $this->serverRequest
            ->withMethod('POST')
            ->withAddedHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withBody($tempStream)
            ->withParsedBody($bodyArray);

        $validatedServerRequest = $this->bearerTokenValidator->validateAuthorization($serverRequest);

        $this->assertSame(
            self::$accessTokenState['id'],
            $validatedServerRequest->getAttribute('oauth_access_token_id'),
        );
    }

    public function testThrowsForUnparsableAccessToken()
    {
        $serverRequest = $this->serverRequest->withAddedHeader('Authorization', 'Bearer ' . 'invalid');

        $this->expectException(OidcServerException::class);

        $this->bearerTokenValidator->validateAuthorization($serverRequest);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testThrowsForExpiredAccessToken()
    {
        $accessTokenState = self::$accessTokenState;
        $accessTokenState['expires_at'] = date('Y-m-d H:i:s', time() - 60);

        $accessTokenEntity = AccessTokenEntity::fromState($accessTokenState);
        $accessTokenEntity->setPrivateKey(self::$privateCryptKey);

        $accessToken = (string) $accessTokenEntity;

        $serverRequest = $this->serverRequest->withAddedHeader('Authorization', 'Bearer ' . $accessToken);

        $this->expectException(OidcServerException::class);

        $this->bearerTokenValidator->validateAuthorization($serverRequest);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Exception
     */
    public function testThrowsForRevokedAccessToken()
    {
        $this->accessTokenRepositoryStub->method('isAccessTokenRevoked')->willReturn(true);

        $bearerTokenValidator = new BearerTokenValidator(
            $this->accessTokenRepositoryStub,
            self::$publicCryptKey,
        );

        $serverRequest = $this->serverRequest->withAddedHeader('Authorization', 'Bearer ' . self::$accessToken);

        $this->expectException(OidcServerException::class);

        $bearerTokenValidator->validateAuthorization($serverRequest);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testThrowsForEmptyAccessTokenJti()
    {
        $accessTokenState = self::$accessTokenState;
        $accessTokenState['id'] = '';

        $accessTokenEntity = AccessTokenEntity::fromState($accessTokenState);
        $accessTokenEntity->setPrivateKey(self::$privateCryptKey);

        $accessToken = (string) $accessTokenEntity;

        $serverRequest = $this->serverRequest->withAddedHeader('Authorization', 'Bearer ' . $accessToken);

        $this->expectException(OidcServerException::class);

        $this->bearerTokenValidator->validateAuthorization($serverRequest);
    }
}
