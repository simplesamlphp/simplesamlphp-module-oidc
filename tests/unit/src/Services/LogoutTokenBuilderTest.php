<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Services;

use Lcobucci\JWT\Signer\Rsa\Sha256;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Factories\CoreFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Associations\Interfaces\RelyingPartyAssociationInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Services\LogoutTokenBuilder;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Core;
use SimpleSAML\OpenID\Core\Factories\LogoutTokenFactory;
use SimpleSAML\OpenID\Jwk\JwkDecorator;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPair;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairBag;

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
    private MockObject $moduleConfigMock;

    /**
     * @var mixed
     */
    private MockObject $relyingPartyAssociationMock;
    private MockObject $loggerServiceMock;
    private MockObject $coreFactoryMock;
    private MockObject $connectSignatureKeyPairBagMock;
    private MockObject $signatureKeyPairMock;
    private MockObject $coreMock;
    private MockObject $logoutTokenFactoryMock;


    /**
     * @throws \ReflectionException
     * @throws \PHPUnit\Framework\MockObject\Exception
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);

        $this->relyingPartyAssociationMock = $this->createMock(RelyingPartyAssociationInterface::class);
        $this->relyingPartyAssociationMock->method('getClientId')->willReturn(self::$clientId);
        $this->relyingPartyAssociationMock->method('getUserId')->willReturn(self::$userId);
        $this->relyingPartyAssociationMock->method('getSessionId')->willReturn(self::$sessionId);
        $this->relyingPartyAssociationMock
            ->method('getBackChannelLogoutUri')
            ->willReturn(self::$backChannelLogoutUri);

        $this->loggerServiceMock = $this->createMock(LoggerService::class);

        $this->coreFactoryMock = $this->createMock(CoreFactory::class);

        $this->connectSignatureKeyPairBagMock = $this->createMock(SignatureKeyPairBag::class);

        $this->signatureKeyPairMock = $this->createMock(SignatureKeyPair::class);
        $this->signatureKeyPairMock->method('getSignatureAlgorithm')
            ->willReturn(SignatureAlgorithmEnum::RS256);

        $this->coreMock = $this->createMock(Core::class);
        $this->coreFactoryMock->method('build')->willReturn($this->coreMock);

        $this->logoutTokenFactoryMock = $this->createMock(LogoutTokenFactory::class);

        $this->coreMock->method('logoutTokenFactory')->willReturn($this->logoutTokenFactoryMock);
    }

    protected function sut(
        ?ModuleConfig $moduleConfig = null,
        ?LoggerService $loggerService = null,
        ?CoreFactory $coreFactory = null,
    ): LogoutTokenBuilder {
        $moduleConfig ??= $this->moduleConfigMock;
        $loggerService ??= $this->loggerServiceMock;
        $coreFactory ??= $this->coreFactoryMock;

        return new LogoutTokenBuilder(
            $moduleConfig,
            $loggerService,
            $coreFactory,
        );
    }

    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(LogoutTokenBuilder::class, $this->sut());
    }

    /**
     * @throws \ReflectionException
     * @throws \Exception
     */
    public function testForRelyingPartyAssociationCallsLogoutTokenFactory(): void
    {
        $this->moduleConfigMock->expects($this->once())
            ->method('getConnectSignatureKeyPairBag')
            ->willReturn($this->connectSignatureKeyPairBagMock);

        $this->connectSignatureKeyPairBagMock->expects($this->once())
            ->method('getFirstOrFail')
            ->willReturn($this->signatureKeyPairMock);

        $this->moduleConfigMock->expects($this->once())
            ->method('getIssuer')
            ->willReturn('issuerId');

        $this->logoutTokenFactoryMock->expects($this->once())
            ->method('fromData')
            ->with(
                $this->isInstanceOf(JwkDecorator::class),
                $this->isInstanceOf(SignatureAlgorithmEnum::class),
                $this->arrayHasKey(ClaimsEnum::Iss->value),
                $this->arrayHasKey(ClaimsEnum::Kid->value),
            );

        $this->sut()->forRelyingPartyAssociation($this->relyingPartyAssociationMock);
    }

    public function testForRelyingPartyAssociationUsesNegotiatedSignatureKeyPair(): void
    {
        $this->moduleConfigMock->expects($this->once())
            ->method('getConnectSignatureKeyPairBag')
            ->willReturn($this->connectSignatureKeyPairBagMock);

        $this->connectSignatureKeyPairBagMock->expects($this->once())
            ->method('getFirstOrFail')
            ->willReturn($this->signatureKeyPairMock);

        $this->relyingPartyAssociationMock->expects($this->once())
            ->method('getClientIdTokenSignedResponseAlg')
            ->willReturn('ES256');

        $negotiatedSignatureKeyPairMock = $this->createMock(SignatureKeyPair::class);
        $negotiatedSignatureKeyPairMock->method('getSignatureAlgorithm')
            ->willReturn(SignatureAlgorithmEnum::ES256);

        $this->connectSignatureKeyPairBagMock->expects($this->once())
            ->method('getFirstByAlgorithmOrFail')
            ->with(SignatureAlgorithmEnum::ES256)
            ->willReturn($negotiatedSignatureKeyPairMock);

        $this->sut()->forRelyingPartyAssociation(
            $this->relyingPartyAssociationMock,
        );
    }
}
