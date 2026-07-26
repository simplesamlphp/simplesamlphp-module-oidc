<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Factories;

use DateInterval;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Factories\FederationFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Codebooks\TrustMarkStatusEndpointUsagePolicyEnum;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\SupportedAlgorithms;

#[CoversClass(FederationFactory::class)]
class FederationFactoryTest extends TestCase
{
    protected MockObject $moduleConfigMock;
    protected MockObject $loggerServiceMock;

    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);

        $this->moduleConfigMock->method('getSupportedAlgorithms')
            ->willReturn(new SupportedAlgorithms());
        $this->moduleConfigMock->method('getFederationCacheMaxDurationForFetched')
            ->willReturn(new DateInterval('PT6H'));
        $this->moduleConfigMock->method('getTimestampValidationLeeway')
            ->willReturn(new DateInterval('PT1M'));
        $this->moduleConfigMock->method('getFederationTrustMarkStatusEndpointUsagePolicy')
            ->willReturn(TrustMarkStatusEndpointUsagePolicyEnum::NotUsed);
        $this->moduleConfigMock->method('getFederationHttpClientOptions')
            ->willReturn([]);
        $this->moduleConfigMock->method('getFederationMaxFetchSizeBytes')
            ->willReturn(102400);
    }

    protected function sut(): FederationFactory
    {
        return new FederationFactory($this->moduleConfigMock, $this->loggerServiceMock);
    }

    public function testCanBuild(): void
    {
        $this->moduleConfigMock->method('getFederationMaxTrustChainDepth')->willReturn(9);
        $this->moduleConfigMock->method('getFederationMaxAuthorityHints')->willReturn(6);
        $this->moduleConfigMock->method('getFederationMaxTrustChainFetches')->willReturn(100);
        $this->moduleConfigMock->method('getFederationTrustChainResolveTimeout')->willReturn(30);

        $this->assertInstanceOf(Federation::class, $this->sut()->build());
    }

    /**
     * Values distinct from the library's own defaults, so that a limit which is not actually wired through
     * shows up as a failure instead of silently falling back.
     */
    public function testPassesConfiguredTraversalLimitsToFederation(): void
    {
        $this->moduleConfigMock->method('getFederationMaxTrustChainDepth')->willReturn(4);
        $this->moduleConfigMock->method('getFederationMaxAuthorityHints')->willReturn(2);
        $this->moduleConfigMock->method('getFederationMaxTrustChainFetches')->willReturn(17);
        $this->moduleConfigMock->method('getFederationTrustChainResolveTimeout')->willReturn(11);

        $federation = $this->sut()->build();

        $this->assertSame(4, $federation->maxTrustChainDepth());
        $this->assertSame(2, $federation->maxAuthorityHints());
        $this->assertSame(17, $federation->maxTrustChainFetches());
        $this->assertSame(11, $federation->trustChainResolveTimeout());
    }
}
