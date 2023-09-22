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
use SimpleSAML\Module\oidc\ConfigurationService;
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
    private $configurationServiceStub;

    public static function setUpBeforeClass(): void
    {
        self::$certFolder = dirname(__DIR__, 3) . '/docker/ssp/';
        self::$privateKeyPath = self::$certFolder . 'oidc_module.key';
        self::$publicKeyPath = self::$certFolder . 'oidc_module.crt';
        self::$signerSha256 = new Sha256();
    }

    public function setUp(): void
    {
        $this->configurationServiceStub = $this->createStub(ConfigurationService::class);
        $this->configurationServiceStub->method('getSigner')->willReturn(self::$signerSha256);
        $this->configurationServiceStub->method('getPrivateKeyPath')->willReturn(self::$privateKeyPath);
        $this->configurationServiceStub->method('getCertPath')->willReturn(self::$publicKeyPath);
        $this->configurationServiceStub->method('getSimpleSAMLSelfURLHost')->willReturn(self::$selfUrlHost);
    }

    /**
     * @throws ReflectionException
     * @throws OAuthServerException
     */
    public function testCanCreateBuilderInstance(): void
    {
        $builderService = new JsonWebTokenBuilderService($this->configurationServiceStub);

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
        $builderService = new JsonWebTokenBuilderService($this->configurationServiceStub);
        $tokenBuilder = $builderService->getDefaultJwtTokenBuilder();

        $unencryptedToken = $builderService->getSignedJwtTokenFromBuilder($tokenBuilder);

        $this->assertInstanceOf(UnencryptedToken::class, $unencryptedToken);
        $this->assertSame(self::$selfUrlHost, $unencryptedToken->claims()->get('iss'));

        // Check token signature
        $token = $unencryptedToken->toString();

        $jwtConfig = Configuration::forAsymmetricSigner(
            $this->configurationServiceStub->getSigner(),
            InMemory::file(
                $this->configurationServiceStub->getPrivateKeyPath(),
                $this->configurationServiceStub->getPrivateKeyPassPhrase() ?? ''
            ),
            InMemory::file($this->configurationServiceStub->getCertPath())
        );

        $parsedToken = $jwtConfig->parser()->parse($token);

        $this->assertTrue(
            $jwtConfig->validator()->validate(
                $parsedToken,
                new IssuedBy(self::$selfUrlHost),
                new SignedWith(
                    $this->configurationServiceStub->getSigner(),
                    InMemory::file($this->configurationServiceStub->getCertPath())
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
            (new JsonWebTokenBuilderService($this->configurationServiceStub))->getSigner()
        );
    }
}
