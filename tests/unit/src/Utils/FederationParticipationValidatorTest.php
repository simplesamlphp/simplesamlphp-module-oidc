<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Utils;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Codebooks\LimitsEnum;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\FederationParticipationValidator;
use SimpleSAML\OpenID\Exceptions\TrustMarkException;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\Federation\EntityStatement;
use SimpleSAML\OpenID\Federation\TrustChain;
use SimpleSAML\OpenID\Federation\TrustMarkValidator;

#[CoversClass(FederationParticipationValidator::class)]
class FederationParticipationValidatorTest extends TestCase
{
    protected MockObject $moduleConfigMock;
    protected MockObject $federationMock;
    protected MockObject $loggerMock;
    protected MockObject $trustMarkValidatorMock;
    protected MockObject $leafEntityConfiguration;
    protected MockObject $trustAnchorEntityConfiguration;
    protected MockObject $trustChainMock;

    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->federationMock = $this->createMock(Federation::class);
        $this->loggerMock = $this->createMock(LoggerService::class);

        $this->trustMarkValidatorMock = $this->createMock(TrustMarkValidator::class);
        $this->federationMock->method('trustMarkValidator')->willReturn($this->trustMarkValidatorMock);

        $this->leafEntityConfiguration = $this->createMock(EntityStatement::class);
        $this->leafEntityConfiguration->method('getIssuer')->willReturn('leafId');
        $this->trustAnchorEntityConfiguration = $this->createMock(EntityStatement::class);
        $this->trustAnchorEntityConfiguration->method('getIssuer')->willReturn('trustAnchorId');

        $this->trustChainMock = $this->createMock(TrustChain::class);
        $this->trustChainMock->method('getResolvedLeaf')
            ->willReturn($this->leafEntityConfiguration);
        $this->trustChainMock->method('getResolvedTrustAnchor')
            ->willReturn($this->trustAnchorEntityConfiguration);
    }

    protected function sut(
        ?ModuleConfig $moduleConfig = null,
        ?Federation $federation = null,
        ?LoggerService $logger = null,
    ): FederationParticipationValidator {
        $moduleConfig ??= $this->moduleConfigMock;
        $federation ??= $this->federationMock;
        $logger ??= $this->loggerMock;

        return new FederationParticipationValidator(
            $moduleConfig,
            $federation,
            $logger,
        );
    }

    public function testCanConstruct(): void
    {
        $this->assertInstanceOf(FederationParticipationValidator::class, $this->sut());
    }

    public function testByTrustMarksFor(): void
    {
        $this->moduleConfigMock->expects($this->once())
            ->method('getTrustMarksNeededForFederationParticipationFor')
            ->with('trustAnchorId')
            ->willReturn([
                LimitsEnum::OneOf->value => ['trustMarkType1'],
                LimitsEnum::AllOf->value => ['trustMarkType2'],
            ]);

        $this->trustMarkValidatorMock->expects($this->atLeastOnce())
            ->method('fromCacheOrDoForTrustMarkType')
            ->with($this->callback(
                fn(string $trustMarkType): bool => in_array($trustMarkType, ['trustMarkType1', 'trustMarkType2']),
            ));

        $this->sut()->byTrustMarksFor($this->trustChainMock);
    }

    public function testByTrustMarksForEmptyLimitsDoesNotRunValidations(): void
    {
        $this->moduleConfigMock->expects($this->once())
            ->method('getTrustMarksNeededForFederationParticipationFor')
            ->with('trustAnchorId')
            ->willReturn([]);

        $this->trustMarkValidatorMock->expects($this->never())
            ->method('fromCacheOrDoForTrustMarkType');

        $this->sut()->byTrustMarksFor($this->trustChainMock);
    }

    public function testValidateForOneOfLimitDoesNotRunValidationOnEmptyLimit(): void
    {
        $this->trustMarkValidatorMock->expects($this->never())
            ->method('fromCacheOrDoForTrustMarkType');

        $this->sut()->validateForOneOfLimit(
            [],
            $this->leafEntityConfiguration,
            $this->trustAnchorEntityConfiguration,
        );
    }

    public function testValidateForOneOfLimitThrowsIfNoneAreValid(): void
    {
        $this->trustMarkValidatorMock->expects($this->atLeastOnce())
            ->method('fromCacheOrDoForTrustMarkType')
            ->with('trustMarkType')
            ->willThrowException(new \Exception('error'));

        $this->expectException(TrustMarkException::class);
        $this->expectExceptionMessage('OneOf limit rule failed');

        $this->sut()->validateForOneOfLimit(
            ['trustMarkType'],
            $this->leafEntityConfiguration,
            $this->trustAnchorEntityConfiguration,
        );
    }

    public function testValidateForAllOfLimitDoesNotRunValidationOnEmptyLimit(): void
    {
        $this->trustMarkValidatorMock->expects($this->never())
            ->method('fromCacheOrDoForTrustMarkType');

        $this->sut()->validateForAllOfLimit(
            [],
            $this->leafEntityConfiguration,
            $this->trustAnchorEntityConfiguration,
        );
    }

    public function testValidateForAllOfLimitThrowsIfAnyIsInvalid(): void
    {
        $this->trustMarkValidatorMock->expects($this->atLeastOnce())
            ->method('fromCacheOrDoForTrustMarkType')
            ->with('trustMarkType')
            ->willThrowException(new \Exception('error'));

        $this->expectException(TrustMarkException::class);
        $this->expectExceptionMessage('AllOf limit rule failed');

        $this->sut()->validateForAllOfLimit(
            ['trustMarkType'],
            $this->leafEntityConfiguration,
            $this->trustAnchorEntityConfiguration,
        );
    }
}
