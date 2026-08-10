<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Factories;

use DateInterval;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Factories\DestinationPolicyFactory;
use SimpleSAML\Module\oidc\Factories\FederationFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Codebooks\TrustMarkStatusEndpointUsagePolicyEnum;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\Network\DestinationPolicy;
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
        $destinationPolicyFactory = $this->createMock(DestinationPolicyFactory::class);
        $destinationPolicyFactory->method('build')->willReturn(new DestinationPolicy());

        return new FederationFactory(
            $this->moduleConfigMock,
            $this->loggerServiceMock,
            $destinationPolicyFactory,
        );
    }

    /**
     * The destination policy must not be built until a Federation is.
     *
     * Building one throws when the outbound configuration is malformed, and the container reaches this
     * factory while wiring up the admin Configuration screens - the screens whose whole purpose is to
     * report such an option. Taking the policy as a constructor dependency made a bad outbound option
     * take those screens down instead of showing up on them, which is how this regressed once already.
     */
    public function testDoesNotBuildTheDestinationPolicyUntilItBuilds(): void
    {
        $destinationPolicyFactory = $this->createMock(DestinationPolicyFactory::class);
        $destinationPolicyFactory->expects($this->never())->method('build');

        new FederationFactory(
            $this->moduleConfigMock,
            $this->loggerServiceMock,
            $destinationPolicyFactory,
        );
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
