<?php

namespace SimpleSAML\Test\Module\oidc\Services;

use Exception;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\RelatedTo;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use ReflectionException;
use SimpleSAML\Module\oidc\Server\Associations\Interfaces\RelyingPartyAssociationInterface;
use SimpleSAML\Module\oidc\Services\ConfigurationService;
use SimpleSAML\Module\oidc\Services\JsonWebTokenBuilderService;
use SimpleSAML\Module\oidc\Services\LogoutTokenBuilder;
use PHPUnit\Framework\TestCase;

/**
 * @covers \SimpleSAML\Module\oidc\Services\LogoutTokenBuilder
 */
class LogoutTokenBuilderTest extends TestCase
{
    private static string $certFolder;
    private static string $privateKeyPath;
    private static string $publicKeyPath;
    private static Sha256 $signerSha256;
    private static string $selfUrlHost = 'https://example.org';

    private static string $clientId = 'client123';
    private static string $userId = 'user123';
    private static string $sessionId = 'session123';
    private static string $backChannelLogoutUri = 'https//some-host.org/logout';
    private static string $logoutTokenType = 'logout+jwt';
    /**
     * @var mixed
     */
    private $configurationServiceStub;
    /**
     * @var mixed
     */
    private $relyingPartyAssociationStub;
    private JsonWebTokenBuilderService $jsonWebTokenBuilderService;

    public static function setUpBeforeClass(): void
    {
        self::$certFolder = dirname(__DIR__, 2) . '/docker/ssp/';
        self::$privateKeyPath = self::$certFolder . 'oidc_module.pem';
        self::$publicKeyPath = self::$certFolder . 'oidc_module.crt';
        self::$signerSha256 = new Sha256();
    }

    /**
     * @throws ReflectionException
     */
    public function setUp(): void
    {
        $this->configurationServiceStub = $this->createStub(ConfigurationService::class);
        $this->configurationServiceStub->method('getSigner')->willReturn(self::$signerSha256);
        $this->configurationServiceStub->method('getPrivateKeyPath')->willReturn(self::$privateKeyPath);
        $this->configurationServiceStub->method('getCertPath')->willReturn(self::$publicKeyPath);
        $this->configurationServiceStub->method('getSimpleSAMLSelfURLHost')->willReturn(self::$selfUrlHost);

        $this->relyingPartyAssociationStub = $this->createStub(RelyingPartyAssociationInterface::class);
        $this->relyingPartyAssociationStub->method('getClientId')->willReturn(self::$clientId);
        $this->relyingPartyAssociationStub->method('getUserId')->willReturn(self::$userId);
        $this->relyingPartyAssociationStub->method('getSessionId')->willReturn(self::$sessionId);
        $this->relyingPartyAssociationStub
            ->method('getBackChannelLogoutUri')
            ->willReturn(self::$backChannelLogoutUri);

        $this->jsonWebTokenBuilderService = new JsonWebTokenBuilderService($this->configurationServiceStub);
    }

    /**
     * @throws ReflectionException
     * @throws Exception
     */
    public function testCanGenerateSignedTokenForRelyingPartyAssociation(): void
    {
        $logoutTokenBuilder = new LogoutTokenBuilder($this->jsonWebTokenBuilderService);

        $token = $logoutTokenBuilder->forRelyingPartyAssociation($this->relyingPartyAssociationStub);

        // Check token validity
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
                new PermittedFor(self::$clientId),
                new RelatedTo(self::$userId),
                new SignedWith(
                    $this->configurationServiceStub->getSigner(),
                    InMemory::file($this->configurationServiceStub->getCertPath())
                )
            )
        );

        $this->assertTrue($parsedToken->headers()->has('typ'));
        $this->assertSame($parsedToken->headers()->get('typ'), self::$logoutTokenType);
    }
}
