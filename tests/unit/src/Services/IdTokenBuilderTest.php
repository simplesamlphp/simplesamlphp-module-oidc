<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Services;

use DateTimeImmutable;
use League\OAuth2\Server\Entities\UserEntityInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\IdTokenBuilder;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Core;
use SimpleSAML\OpenID\Core\Factories\IdTokenFactory;
use SimpleSAML\OpenID\Core\IdToken;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPair;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairBag;

#[CoversClass(IdTokenBuilder::class)]
class IdTokenBuilderTest extends TestCase
{
    protected MockObject $claimTranslatorExtractorMock;
    protected MockObject $coreMock;
    protected MockObject $moduleConfigMock;
    protected MockObject $protocolSignatureKeyBagMock;
    protected MockObject $protocolSignatureKeyPairMock;
    protected MockObject $idTokenFactoryMock;
    protected MockObject $userEntityMock;
    protected MockObject $accessTokenEntityMock;
    protected MockObject $clientEntityMock;
    protected MockObject $accessTokenExpiryDateTimeMock;
    protected MockObject $scopeEntityMock;

    protected function setUp(): void
    {
        $this->claimTranslatorExtractorMock = $this->createMock(ClaimTranslatorExtractor::class);
        $this->coreMock = $this->createMock(Core::class);
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);

        $this->protocolSignatureKeyBagMock = $this->createMock(SignatureKeyPairBag::class);

        $this->moduleConfigMock->method('getProtocolSignatureKeyPairBag')
            ->willReturn($this->protocolSignatureKeyBagMock);

        $this->protocolSignatureKeyPairMock = $this->createMock(SignatureKeyPair::class);
        $this->protocolSignatureKeyPairMock->method('getSignatureAlgorithm')
            ->willReturn(SignatureAlgorithmEnum::RS256);

        $this->protocolSignatureKeyBagMock->method('getFirstOrFail')
            ->willReturn($this->protocolSignatureKeyPairMock);


        $this->idTokenFactoryMock = $this->createMock(IdTokenFactory::class);
        $this->coreMock->method('idTokenFactory')->willReturn($this->idTokenFactoryMock);

        $this->userEntityMock = $this->createMock(UserEntity::class);
        $this->accessTokenEntityMock = $this->createMock(AccessTokenEntity::class);


        $this->clientEntityMock = $this->createMock(ClientEntity::class);
        $this->accessTokenEntityMock->method('getClient')->willReturn($this->clientEntityMock);

        $this->accessTokenExpiryDateTimeMock = $this->createMock(DateTimeImmutable::class);
        $this->accessTokenEntityMock->method('getExpiryDateTime')
            ->willReturn($this->accessTokenExpiryDateTimeMock);

        $this->scopeEntityMock = $this->createMock(ScopeEntity::class);
        $this->accessTokenEntityMock->method('getScopes')->willReturn([$this->scopeEntityMock]);
    }

    protected function sut(
        ?ClaimTranslatorExtractor $claimTranslatorExtractor = null,
        ?Core $core = null,
        ?ModuleConfig $moduleConfig = null,
    ): IdTokenBuilder {
        $claimTranslatorExtractor ??= $this->claimTranslatorExtractorMock;
        $core ??= $this->coreMock;
        $moduleConfig ??= $this->moduleConfigMock;

        return new IdTokenBuilder(
            $claimTranslatorExtractor,
            $core,
            $moduleConfig,
        );
    }

    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(IdTokenBuilder::class, $this->sut());
    }

    public function testCanBuild(): void
    {
        $this->moduleConfigMock->expects($this->once())->method('getIssuer')
            ->willReturn('issuer');
        $this->idTokenFactoryMock->expects($this->once())->method('fromData')
            ->with(
                $this->anything(),
                SignatureAlgorithmEnum::RS256,
                $this->arrayHasKey(ClaimsEnum::Iss->value),
            );

        $this->claimTranslatorExtractorMock->expects($this->once())
            ->method('extract')
            ->willReturn(['foo' => 'bar']);

        $this->claimTranslatorExtractorMock->expects($this->once())
            ->method('extractAdditionalIdTokenClaims')
            ->willReturn(['additional' => 'claim']);

        $this->assertInstanceOf(
            IdToken::class,
            $this->sut()->buildFor(
                $this->userEntityMock,
                $this->accessTokenEntityMock,
                true,
                true,
                null,
                null,
                null,
                null,
            ),
        );
    }

    public function testWillNegotiateIdTokenSignatureAlgorithm(): void
    {
        $this->clientEntityMock->method('getIdTokenSignedResponseAlg')
            ->willReturn(SignatureAlgorithmEnum::ES256->value);

        $ecSignatureKeyPairMock = $this->createMock(SignatureKeyPair::class);
        $ecSignatureKeyPairMock->method('getSignatureAlgorithm')
            ->willReturn(SignatureAlgorithmEnum::ES256);

        $this->protocolSignatureKeyBagMock->expects($this->once())
            ->method('getFirstByAlgorithmOrFail')
            ->with(SignatureAlgorithmEnum::ES256)
            ->willReturn($ecSignatureKeyPairMock);

        $this->assertInstanceOf(
            IdToken::class,
            $this->sut()->buildFor(
                $this->userEntityMock,
                $this->accessTokenEntityMock,
                true,
                true,
                null,
                null,
                null,
                null,
            ),
        );
    }

    public function testThrowsForInvalidUserEntity(): void
    {
        $userEntityInterfaceMock = $this->createMock(UserEntityInterface::class);
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('ClaimSetInterface');

        $this->sut()->buildFor(
            $userEntityInterfaceMock,
            $this->accessTokenEntityMock,
            true,
            true,
            null,
            null,
            null,
            null,
        );
    }

    public function testThrowsForInvalidClientEntity(): void
    {
        $accessTokenEntityMock = $this->createMock(AccessTokenEntity::class);
        $accessTokenEntityMock->method('getClient')->willReturn(
            $this->createMock(\League\OAuth2\Server\Entities\ClientEntityInterface::class),
        );

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('ClientEntity');

        $this->sut()->buildFor(
            $this->userEntityMock,
            $accessTokenEntityMock,
            true,
            true,
            null,
            null,
            null,
            null,
        );
    }
}
