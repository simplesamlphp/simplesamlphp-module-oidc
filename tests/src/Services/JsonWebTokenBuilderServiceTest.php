<?php

namespace SimpleSAML\Test\Module\oidc\Services;

use Exception;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use League\OAuth2\Server\Exception\OAuthServerException;
use PHPUnit\Framework\TestCase;
use ReflectionException;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\JsonWebTokenBuilderService;

/**
 * @covers \SimpleSAML\Module\oidc\Services\JsonWebTokenBuilderService
 */
class JsonWebTokenBuilderServiceTest extends TestCase
{
    private static string $certFolder;
    private static string $privateKeyPath;
    private static string $publicKeyPath;
    private static Sha256 $signerSha256;
    private static string $selfUrlHost = 'https://example.org';
    /**
     * @var mixed
     */
    private $moduleConfigStub;

    public static function setUpBeforeClass(): void
    {
        self::$certFolder = dirname(__DIR__, 3) . '/docker/ssp/';
        self::$privateKeyPath = self::$certFolder . ModuleConfig::DEFAULT_PKI_PRIVATE_KEY_FILENAME;
        self::$publicKeyPath = self::$certFolder . ModuleConfig::DEFAULT_PKI_CERTIFICATE_FILENAME;
        self::$signerSha256 = new Sha256();
    }

    public function setUp(): void
    {
        $this->moduleConfigStub = $this->createStub(ModuleConfig::class);
        $this->moduleConfigStub->method('getSigner')->willReturn(self::$signerSha256);
        $this->moduleConfigStub->method('getPrivateKeyPath')->willReturn(self::$privateKeyPath);
        $this->moduleConfigStub->method('getCertPath')->willReturn(self::$publicKeyPath);
        $this->moduleConfigStub->method('getSimpleSAMLSelfURLHost')->willReturn(self::$selfUrlHost);
    }

    /**
     * @throws ReflectionException
     * @throws OAuthServerException
     */
    public function testCanCreateBuilderInstance(): void
    {
        $builderService = new JsonWebTokenBuilderService($this->moduleConfigStub);

        $this->assertInstanceOf(
            Builder::class,
            $builderService->getDefaultJwtTokenBuilder()
        );
    }

    /**
     * @throws ReflectionException
     * @throws OAuthServerException
     * @throws Exception
     */
    public function testCanGenerateSignedJwtToken(): void
    {
        $builderService = new JsonWebTokenBuilderService($this->moduleConfigStub);
        $tokenBuilder = $builderService->getDefaultJwtTokenBuilder();

        $unencryptedToken = $builderService->getSignedJwtTokenFromBuilder($tokenBuilder);

        $this->assertInstanceOf(UnencryptedToken::class, $unencryptedToken);
        $this->assertSame(self::$selfUrlHost, $unencryptedToken->claims()->get('iss'));

        // Check token signature
        $token = $unencryptedToken->toString();

        $jwtConfig = Configuration::forAsymmetricSigner(
            $this->moduleConfigStub->getSigner(),
            InMemory::file(
                $this->moduleConfigStub->getPrivateKeyPath(),
                $this->moduleConfigStub->getPrivateKeyPassPhrase() ?? ''
            ),
            InMemory::file($this->moduleConfigStub->getCertPath())
        );

        $parsedToken = $jwtConfig->parser()->parse($token);

        $this->assertTrue(
            $jwtConfig->validator()->validate(
                $parsedToken,
                new IssuedBy(self::$selfUrlHost),
                new SignedWith(
                    $this->moduleConfigStub->getSigner(),
                    InMemory::file($this->moduleConfigStub->getCertPath())
                )
            )
        );
    }

    /**
     * @throws ReflectionException
     */
    public function testCanReturnCurrentSigner(): void
    {
        $this->assertSame(
            self::$signerSha256,
            (new JsonWebTokenBuilderService($this->moduleConfigStub))->getSigner()
        );
    }
}
