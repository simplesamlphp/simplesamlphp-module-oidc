<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Services;

use DateInterval;
use DateTimeImmutable;
use DateTimeZone;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
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
use SimpleSAML\OpenID\Helpers;
use SimpleSAML\OpenID\Helpers\DateTime;
use SimpleSAML\OpenID\Jwk\JwkDecorator;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPair;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairBag;

#[CoversClass(LogoutTokenBuilder::class)]
#[AllowMockObjectsWithoutExpectations]
class LogoutTokenBuilderTest extends TestCase
{
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

    private MockObject $protocolSignatureKeyPairBagMock;

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

        $this->protocolSignatureKeyPairBagMock = $this->createMock(SignatureKeyPairBag::class);

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
            ->method('getProtocolSignatureKeyPairBag')
            ->willReturn($this->protocolSignatureKeyPairBagMock);

        $this->protocolSignatureKeyPairBagMock->expects($this->once())
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
            ->method('getProtocolSignatureKeyPairBag')
            ->willReturn($this->protocolSignatureKeyPairBagMock);

        $this->protocolSignatureKeyPairBagMock->expects($this->once())
            ->method('getFirstOrFail')
            ->willReturn($this->signatureKeyPairMock);

        $this->relyingPartyAssociationMock->expects($this->once())
            ->method('getClientIdTokenSignedResponseAlg')
            ->willReturn('ES256');

        $negotiatedSignatureKeyPairMock = $this->createMock(SignatureKeyPair::class);
        $negotiatedSignatureKeyPairMock->method('getSignatureAlgorithm')
            ->willReturn(SignatureAlgorithmEnum::ES256);

        $this->protocolSignatureKeyPairBagMock->expects($this->once())
            ->method('getFirstByAlgorithmOrFail')
            ->with(SignatureAlgorithmEnum::ES256)
            ->willReturn($negotiatedSignatureKeyPairMock);

        $this->sut()->forRelyingPartyAssociation(
            $this->relyingPartyAssociationMock,
        );
    }


    /**
     * Issued now and expiring the configured duration later, both from one reading of the clock. The clock here
     * advances a second per reading, so a second reading as the base for `exp` would show as a second more.
     *
     * @throws \Exception
     */
    public function testTheLogoutTokenIsIssuedNowAndExpiresAfterTheConfiguredDuration(): void
    {
        $now = new DateTimeImmutable('2026-11-14 10:00:00', new DateTimeZone('UTC'));
        $clockReads = 0;
        $dateTimeHelperStub = $this->createStub(DateTime::class);
        $dateTimeHelperStub->method('getUtc')->willReturnCallback(
            static function () use ($now, &$clockReads): DateTimeImmutable {
                return $now->modify(sprintf('+%d seconds', $clockReads++));
            },
        );
        $helpersStub = $this->createStub(Helpers::class);
        $helpersStub->method('dateTime')->willReturn($dateTimeHelperStub);
        $this->coreMock->method('helpers')->willReturn($helpersStub);
        $this->moduleConfigMock->method('getProtocolSignatureKeyPairBag')
            ->willReturn($this->protocolSignatureKeyPairBagMock);
        $this->protocolSignatureKeyPairBagMock->method('getFirstOrFail')->willReturn($this->signatureKeyPairMock);
        $this->moduleConfigMock->method('getAuthCodeDuration')->willReturn(new DateInterval('PT7M'));
        $payload = null;
        $this->logoutTokenFactoryMock->expects($this->once())->method('fromData')->with(
            $this->anything(),
            $this->anything(),
            $this->callback(static function (array $claims) use (&$payload): bool {
                $payload = $claims;
                return true;
            }),
            $this->anything(),
        );

        $this->sut()->forRelyingPartyAssociation($this->relyingPartyAssociationMock);

        $this->assertIsArray($payload);
        $this->assertSame($now->getTimestamp(), $payload[ClaimsEnum::Iat->value] ?? null);
        $this->assertSame($now->getTimestamp() + 420, $payload[ClaimsEnum::Exp->value] ?? null);
    }
}
