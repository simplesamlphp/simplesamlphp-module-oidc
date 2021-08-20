<?php

namespace SimpleSAML\Test\Module\oidc\Server\Validators;

use Lcobucci\JWT\Signer\Key\InMemory;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface as OAuth2AccessTokenRepositoryInterface;
use PHP_CodeSniffer\Tests\Core\Autoloader\B;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Entity\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entity\ClientEntity;
use SimpleSAML\Module\oidc\Entity\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Entity\ScopeEntity;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Server\Validators\BearerTokenValidator;

/**
 * @covers \SimpleSAML\Module\oidc\Server\Validators\BearerTokenValidator
 */
class BearerTokenValidatorTest extends TestCase
{
    /**
     * @var AccessTokenEntity
     */
    protected static $accessTokenEntity;

    /**
     * @var string
     */
    protected static $privateKeyPath;

    /**
     * @var CryptKey
     */
    protected static $privateCryptKey;

    /**
     * @var BearerTokenValidator
     */
    protected $bearerTokenValidator;

    /**
     * @var string
     */
    protected static $privateKey;

    /**
     * @var string
     */
    protected static $publicKey;

    /**
     * @var CryptKey
     */
    protected static $publicCryptKey;

    /**
     * @var string
     */
    protected static $publicKeyPath;

    /**
     * @var OAuth2AccessTokenRepositoryInterface
     */
    protected $accessTokenRepositoryStub;

    /**
     * @var ClientEntityInterface
     */
    protected static $clientEntity;

    public function setUp(): void
    {
        $this->accessTokenRepositoryStub = $this->createStub(AccessTokenRepository::class);
    }

    public static function setUpBeforeClass(): void
    {
        self::$publicKeyPath = sys_get_temp_dir() . '/oidc_module.crt';
        self::$privateKeyPath = sys_get_temp_dir() . '/oidc_module.key';

        $pkGenerate = openssl_pkey_new([
                                           'private_key_bits' => 1024,
                                           'private_key_type' => OPENSSL_KEYTYPE_RSA,
                                       ]);

        // get the private key
        openssl_pkey_export($pkGenerate, self::$privateKey);

        // get the public key
        self::$publicKey = openssl_pkey_get_details($pkGenerate)['key'];

        file_put_contents(self::$publicKeyPath, self::$publicKey);
        file_put_contents(self::$privateKeyPath, self::$privateKey);
        \chmod(self::$publicKeyPath, 0600);
        \chmod(self::$privateKeyPath, 0600);

        self::$publicCryptKey = new CryptKey(self::$publicKeyPath);
        self::$privateCryptKey = new CryptKey(self::$privateKeyPath);

        self::$clientEntity = ClientEntity::fromData('id1', 'secret1', 'name1', 'desc1', ['redirect-uri'], ['openid'], true);

        self::$accessTokenEntity = AccessTokenEntity::fromData(self::$clientEntity, [ScopeEntity::fromData('openid')]);
        self::$accessTokenEntity->setPrivateKey(self::$privateCryptKey);
    }

    /**
     * @return void
     */
    public static function tearDownAfterClass(): void
    {
        unlink(self::$publicKeyPath);
        unlink(self::$privateKeyPath);
    }

    public function testConstruct()
    {
        $bearerTokenValidator = new BearerTokenValidator($this->accessTokenRepositoryStub);
        $bearerTokenValidator->setPublicKey(self::$publicCryptKey);
    }
}
