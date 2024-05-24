<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Services;

use PHPUnit\Framework\MockObject\Stub;
use Exception;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\RelatedTo;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use PHPUnit\Framework\TestCase;
use ReflectionException;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Associations\Interfaces\RelyingPartyAssociationInterface;
use SimpleSAML\Module\oidc\Services\JsonWebTokenBuilderService;
use SimpleSAML\Module\oidc\Services\LogoutTokenBuilder;

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
    private Stub $moduleConfigStub;
    /**
     * @var mixed
     */
    private Stub $relyingPartyAssociationStub;
    private JsonWebTokenBuilderService $jsonWebTokenBuilderService;

    public static function setUpBeforeClass(): void
    {
        self::$certFolder = dirname(__DIR__, 3) . '/docker/ssp/';
        self::$privateKeyPath = self::$certFolder . ModuleConfig::DEFAULT_PKI_PRIVATE_KEY_FILENAME;
        self::$publicKeyPath = self::$certFolder . ModuleConfig::DEFAULT_PKI_CERTIFICATE_FILENAME;
        self::$signerSha256 = new Sha256();
    }

    /**
     * @throws ReflectionException
     * @throws \PHPUnit\Framework\MockObject\Exception
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function setUp(): void
    {
        $this->moduleConfigStub = $this->createStub(ModuleConfig::class);
        $this->moduleConfigStub->method('getSigner')->willReturn(self::$signerSha256);
        $this->moduleConfigStub->method('getPrivateKeyPath')->willReturn(self::$privateKeyPath);
        $this->moduleConfigStub->method('getCertPath')->willReturn(self::$publicKeyPath);
        $this->moduleConfigStub->method('getSimpleSAMLSelfURLHost')->willReturn(self::$selfUrlHost);

        $this->relyingPartyAssociationStub = $this->createStub(RelyingPartyAssociationInterface::class);
        $this->relyingPartyAssociationStub->method('getClientId')->willReturn(self::$clientId);
        $this->relyingPartyAssociationStub->method('getUserId')->willReturn(self::$userId);
        $this->relyingPartyAssociationStub->method('getSessionId')->willReturn(self::$sessionId);
        $this->relyingPartyAssociationStub
            ->method('getBackChannelLogoutUri')
            ->willReturn(self::$backChannelLogoutUri);

        $this->jsonWebTokenBuilderService = new JsonWebTokenBuilderService($this->moduleConfigStub);
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
            $this->moduleConfigStub->getSigner(),
            InMemory::file(
                $this->moduleConfigStub->getPrivateKeyPath(),
                $this->moduleConfigStub->getPrivateKeyPassPhrase() ?? '',
            ),
            InMemory::file($this->moduleConfigStub->getCertPath()),
        );

        $parsedToken = $jwtConfig->parser()->parse($token);

        $this->assertTrue(
            $jwtConfig->validator()->validate(
                $parsedToken,
                new IssuedBy(self::$selfUrlHost),
                new PermittedFor(self::$clientId),
                new RelatedTo(self::$userId),
                new SignedWith(
                    $this->moduleConfigStub->getSigner(),
                    InMemory::file($this->moduleConfigStub->getCertPath()),
                ),
            ),
        );

        $this->assertTrue($parsedToken->headers()->has('typ'));
        $this->assertSame($parsedToken->headers()->get('typ'), self::$logoutTokenType);
    }
}
