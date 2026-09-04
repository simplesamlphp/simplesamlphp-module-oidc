<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Factories;

use DateInterval;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Exceptions\OidcException;
use SimpleSAML\Module\oidc\Factories\CacheFactory;
use SimpleSAML\Module\oidc\Factories\DestinationPolicyFactory;
use SimpleSAML\Module\oidc\Factories\FederationFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\ClassInstanceBuilder;
use SimpleSAML\OpenID\Codebooks\TrustMarkStatusEndpointUsagePolicyEnum;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\Network\DestinationPolicy;
use SimpleSAML\OpenID\SupportedAlgorithms;
use Throwable;

#[CoversClass(FederationFactory::class)]
#[AllowMockObjectsWithoutExpectations]
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
            $this->createMock(CacheFactory::class),
        );
    }


    /**
     * Neither collaborator may be built until a Federation is.
     *
     * Building either throws when the configuration behind it is malformed, and the container reaches
     * this factory while wiring up the admin Configuration screens - the screens whose whole purpose is
     * to report such an option. Taking a built one as a constructor dependency made a bad option take
     * those screens down instead of showing up on them. That happened twice: first with the destination
     * policy, then again with the cache, which was left injected when the policy was moved behind its
     * factory.
     */
    public function testDoesNotBuildItsCollaboratorsUntilItBuilds(): void
    {
        $destinationPolicyFactory = $this->createMock(DestinationPolicyFactory::class);
        $destinationPolicyFactory->expects($this->never())->method('build');

        $cacheFactory = $this->createMock(CacheFactory::class);
        $cacheFactory->expects($this->never())->method('forFederation');

        new FederationFactory(
            $this->moduleConfigMock,
            $this->loggerServiceMock,
            $destinationPolicyFactory,
            $cacheFactory,
        );
    }


    /**
     * Constructing this factory must not read the cache configuration at all.
     *
     * Uses a real CacheFactory over a real ModuleConfig carrying a malformed adapter option, which is
     * the shape the container produces and the only one that reproduces the fault: mocked collaborators
     * never read configuration, so every other test here would pass with the cache injected as before.
     *
     * @throws \Exception
     */
    public function testAMalformedCacheAdapterDoesNotBreakConstruction(): void
    {
        $moduleConfig = new ModuleConfig(
            ModuleConfig::DEFAULT_FILE_NAME,
            [ModuleConfig::OPTION_FEDERATION_CACHE_ADAPTER => 123],
            $this->createMock(Configuration::class),
        );

        $cacheFactory = new CacheFactory(
            $moduleConfig,
            $this->loggerServiceMock,
            new ClassInstanceBuilder(),
        );

        // The container reaches this constructor while wiring the admin Configuration screens up, so a
        // throw here would take down the screen that exists to report exactly this option.
        $sut = new FederationFactory(
            $moduleConfig,
            $this->loggerServiceMock,
            $this->createMock(DestinationPolicyFactory::class),
            $cacheFactory,
        );

        // And the deferred read still fails, where the caller catches it rather than the container.
        $this->expectException(Throwable::class);

        $sut->build();
    }


    /**
     * A cache adapter which cannot be built must surface from build(), where the one caller that has to
     * survive it - the federation configuration screen - already catches it.
     */
    public function testACacheWhichCannotBeBuiltSurfacesFromBuild(): void
    {
        $this->moduleConfigMock->method('getFederationMaxTrustChainDepth')->willReturn(9);
        $this->moduleConfigMock->method('getFederationMaxAuthorityHints')->willReturn(6);
        $this->moduleConfigMock->method('getFederationMaxTrustChainFetches')->willReturn(100);
        $this->moduleConfigMock->method('getFederationTrustChainResolveTimeout')->willReturn(30);

        $destinationPolicyFactory = $this->createMock(DestinationPolicyFactory::class);
        $destinationPolicyFactory->method('build')->willReturn(new DestinationPolicy());

        $cacheFactory = $this->createMock(CacheFactory::class);
        $cacheFactory->method('forFederation')
            ->willThrowException(new OidcException('Unusable cache adapter.'));

        $sut = new FederationFactory(
            $this->moduleConfigMock,
            $this->loggerServiceMock,
            $destinationPolicyFactory,
            $cacheFactory,
        );

        $this->expectException(OidcException::class);

        $sut->build();
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
