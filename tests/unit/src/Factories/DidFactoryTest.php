<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Factories;

use DateInterval;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Factories\CacheFactory;
use SimpleSAML\Module\oidc\Factories\DidFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\VciCache;
use SimpleSAML\OpenID\Codebooks\AddressPinningModeEnum;
use SimpleSAML\OpenID\Did;
use SimpleSAML\OpenID\Network\DestinationPolicy;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Cache\Psr16Cache;

#[CoversClass(DidFactory::class)]
#[AllowMockObjectsWithoutExpectations]
class DidFactoryTest extends TestCase
{
    protected MockObject $moduleConfigMock;

    protected MockObject $loggerServiceMock;


    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);

        $this->moduleConfigMock->method('getVciDidCacheMaxDuration')
            ->willReturn(new DateInterval('PT6H'));
        $this->moduleConfigMock->method('getVciDidAddressPinningMode')
            ->willReturn(AddressPinningModeEnum::Required);
        $this->moduleConfigMock->method('getVciDidOutboundAllowedHosts')
            ->willReturn([]);
        $this->moduleConfigMock->method('getVciDidOutboundAllowedCidrs')
            ->willReturn([]);
    }


    protected function sut(): DidFactory
    {
        return new DidFactory(
            $this->moduleConfigMock,
            $this->loggerServiceMock,
        );
    }


    /**
     * Nothing may be resolved from configuration until a Did is built.
     *
     * A malformed exemption makes the destination policy throw, and the container reaches this factory
     * while wiring up the admin Configuration screens - the screens whose whole purpose is to report
     * such an option. Resolving in the constructor would take those screens down instead of showing the
     * problem on them, which is how FederationFactory regressed once.
     */
    public function testDoesNotResolveConfigurationUntilItBuilds(): void
    {
        $moduleConfigMock = $this->createMock(ModuleConfig::class);
        $moduleConfigMock->expects($this->never())->method('getVciDidAddressPinningMode');
        $moduleConfigMock->expects($this->never())->method('getVciDidOutboundAllowedHosts');
        $moduleConfigMock->expects($this->never())->method('getVciDidOutboundAllowedCidrs');
        $moduleConfigMock->expects($this->never())->method('getVciDidCacheMaxDuration');

        new DidFactory($moduleConfigMock, $this->loggerServiceMock);
    }


    public function testCanBuild(): void
    {
        $this->assertInstanceOf(Did::class, $this->sut()->build());
    }


    /**
     * The policy handed to DID resolution must be the DID one, not the deployment's general outbound
     * policy: pinning required rather than merely preferred, and https alone.
     */
    public function testBuildsARestrictiveDestinationPolicy(): void
    {
        $destinationPolicy = $this->sut()->build()->destinationPolicy();

        $this->assertSame(
            AddressPinningModeEnum::Required,
            $destinationPolicy->getAddressPinningMode(),
        );
        $this->assertSame(
            DestinationPolicy::DEFAULT_ALLOWED_SCHEMES,
            $destinationPolicy->getAllowedSchemes(),
        );
        $this->assertSame([], $destinationPolicy->getAllowedHosts());
        $this->assertSame([], $destinationPolicy->getAllowedCidrs());
    }


    /**
     * The DID-specific exemptions reach the policy. Values distinct from anything defaulted, so an
     * option which is not actually wired through shows up as a failure rather than passing by accident.
     */
    public function testPassesConfiguredExemptionsToTheDestinationPolicy(): void
    {
        $moduleConfigMock = $this->createMock(ModuleConfig::class);
        $moduleConfigMock->method('getVciDidCacheMaxDuration')->willReturn(new DateInterval('PT1H'));
        $moduleConfigMock->method('getVciDidAddressPinningMode')
            ->willReturn(AddressPinningModeEnum::Disabled);
        $moduleConfigMock->method('getVciDidOutboundAllowedHosts')
            ->willReturn(['wallet.internal.example']);
        $moduleConfigMock->method('getVciDidOutboundAllowedCidrs')->willReturn(['10.1.2.3/32']);

        $destinationPolicy = (new DidFactory($moduleConfigMock, $this->loggerServiceMock))
            ->build()
            ->destinationPolicy();

        $this->assertSame(
            AddressPinningModeEnum::Disabled,
            $destinationPolicy->getAddressPinningMode(),
        );
        $this->assertSame(['wallet.internal.example'], $destinationPolicy->getAllowedHosts());
        $this->assertSame(['10.1.2.3/32'], $destinationPolicy->getAllowedCidrs());
    }


    /**
     * The cache is a decorator around the PSR-16 instance the library wants, so the factory has to
     * unwrap it. Passing the decorator itself would be a type error rather than a silent miss, but a
     * later change to how it is unwrapped would not be.
     */
    public function testAcceptsAConfiguredCache(): void
    {
        $vciCache = new VciCache(new Psr16Cache(new ArrayAdapter()));

        $cacheFactoryMock = $this->createMock(CacheFactory::class);
        $cacheFactoryMock->method('forVci')->willReturn($vciCache);

        $this->assertInstanceOf(
            Did::class,
            (new DidFactory($this->moduleConfigMock, $this->loggerServiceMock, $cacheFactoryMock))->build(),
        );
    }


    /**
     * The cache is asked for when the facade is built, not when this factory is constructed. Building
     * the adapter reads `vci_cache_adapter` and instantiates the class it names, so a caller holding
     * this factory for something else - the metadata document's DID method list, say - must not inherit
     * that failure.
     */
    public function testTheCacheIsNotBuiltUntilTheFacadeIs(): void
    {
        $forVciCalls = 0;

        $cacheFactoryMock = $this->createMock(CacheFactory::class);
        $cacheFactoryMock->method('forVci')->willReturnCallback(
            function () use (&$forVciCalls): ?VciCache {
                $forVciCalls++;

                return null;
            },
        );

        $didFactory = new DidFactory($this->moduleConfigMock, $this->loggerServiceMock, $cacheFactoryMock);

        $this->assertSame(0, $forVciCalls);

        $this->assertInstanceOf(Did::class, $didFactory->build());
        $this->assertSame(1, $forVciCalls);
    }


    /**
     * An exemption is a destination that whoever supplies a DID may send this deployment to, so the
     * library notices it. The factory has to hand over a logger for that to be recorded anywhere.
     */
    public function testAnExemptionIsReportedToTheLog(): void
    {
        $this->loggerServiceMock->expects($this->once())->method('notice');

        $moduleConfigMock = $this->createMock(ModuleConfig::class);
        $moduleConfigMock->method('getVciDidCacheMaxDuration')->willReturn(new DateInterval('PT6H'));
        $moduleConfigMock->method('getVciDidAddressPinningMode')
            ->willReturn(AddressPinningModeEnum::Required);
        $moduleConfigMock->method('getVciDidOutboundAllowedHosts')
            ->willReturn(['wallet.internal.example']);
        $moduleConfigMock->method('getVciDidOutboundAllowedCidrs')->willReturn([]);

        (new DidFactory($moduleConfigMock, $this->loggerServiceMock))->build();
    }
}
