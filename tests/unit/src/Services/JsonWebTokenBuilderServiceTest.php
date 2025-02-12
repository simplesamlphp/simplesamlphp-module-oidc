<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Services;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
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
    private Stub $moduleConfigStub;

    public static function setUpBeforeClass(): void
    {
        self::$certFolder = dirname(__DIR__, 4) . '/docker/ssp/';
        self::$privateKeyPath = self::$certFolder . ModuleConfig::DEFAULT_PKI_PRIVATE_KEY_FILENAME;
        self::$publicKeyPath = self::$certFolder . ModuleConfig::DEFAULT_PKI_CERTIFICATE_FILENAME;
        self::$signerSha256 = new Sha256();
    }

    /**
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function setUp(): void
    {
        $this->moduleConfigStub = $this->createStub(ModuleConfig::class);
        $this->moduleConfigStub->method('getProtocolSigner')->willReturn(self::$signerSha256);
        $this->moduleConfigStub->method('getProtocolPrivateKeyPath')->willReturn(self::$privateKeyPath);
        $this->moduleConfigStub->method('getProtocolCertPath')->willReturn(self::$publicKeyPath);
        $this->moduleConfigStub->method('getIssuer')->willReturn(self::$selfUrlHost);
    }

    /**
     * @throws \ReflectionException
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    public function testCanCreateBuilderInstance(): void
    {
        $builderService = new JsonWebTokenBuilderService($this->moduleConfigStub);

        $this->assertInstanceOf(
            Builder::class,
            $builderService->getProtocolJwtBuilder(),
        );
    }

    /**
     * @throws \ReflectionException
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \Exception
     */
    public function testCanGenerateSignedJwtToken(): void
    {
        $builderService = new JsonWebTokenBuilderService($this->moduleConfigStub);
        $tokenBuilder = $builderService->getProtocolJwtBuilder();

        $unencryptedToken = $builderService->getSignedProtocolJwt($tokenBuilder);

        $this->assertInstanceOf(UnencryptedToken::class, $unencryptedToken);
        $this->assertSame(self::$selfUrlHost, $unencryptedToken->claims()->get('iss'));

        // Check token signature
        $token = $unencryptedToken->toString();

        $jwtConfig = Configuration::forAsymmetricSigner(
            $this->moduleConfigStub->getProtocolSigner(),
            InMemory::file(
                $this->moduleConfigStub->getProtocolPrivateKeyPath(),
                $this->moduleConfigStub->getProtocolPrivateKeyPassPhrase() ?? '',
            ),
            InMemory::file($this->moduleConfigStub->getProtocolCertPath()),
        );

        $parsedToken = $jwtConfig->parser()->parse($token);

        $this->assertTrue(
            $jwtConfig->validator()->validate(
                $parsedToken,
                new IssuedBy(self::$selfUrlHost),
                new SignedWith(
                    $this->moduleConfigStub->getProtocolSigner(),
                    InMemory::file($this->moduleConfigStub->getProtocolCertPath()),
                ),
            ),
        );
    }

    /**
     * @throws \ReflectionException
     */
    public function testCanReturnCurrentSigner(): void
    {
        $this->assertSame(
            self::$signerSha256,
            (new JsonWebTokenBuilderService($this->moduleConfigStub))->getProtocolSigner(),
        );
    }
}
