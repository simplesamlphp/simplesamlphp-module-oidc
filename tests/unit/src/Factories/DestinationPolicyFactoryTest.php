<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Factories;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Factories\DestinationPolicyFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Codebooks\AddressPinningModeEnum;
use SimpleSAML\OpenID\Exceptions\DestinationPolicyException;
use SimpleSAML\OpenID\Network\DestinationPolicy;

/**
 * Every assertion here is chosen to avoid a DNS lookup: an allow-listed host skips resolution, a scheme is
 * rejected before any name is looked up, and an address given directly has nothing to resolve. A unit test
 * that reaches a resolver is one that fails on a train.
 */
#[CoversClass(DestinationPolicyFactory::class)]
class DestinationPolicyFactoryTest extends TestCase
{
    protected MockObject $moduleConfigMock;

    protected MockObject $loggerServiceMock;

    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);

        $this->configure();
    }

    /**
     * @param list<string> $allowedSchemes
     * @param list<string> $allowedHosts
     * @param list<string> $allowedCidrs
     */
    protected function configure(
        array $allowedSchemes = ['https'],
        array $allowedHosts = [],
        array $allowedCidrs = [],
        AddressPinningModeEnum $pinningMode = AddressPinningModeEnum::Preferred,
    ): void {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getOutboundAllowedSchemes')->willReturn($allowedSchemes);
        $this->moduleConfigMock->method('getOutboundAllowedHosts')->willReturn($allowedHosts);
        $this->moduleConfigMock->method('getOutboundAllowedCidrs')->willReturn($allowedCidrs);
        $this->moduleConfigMock->method('getOutboundAddressPinningMode')->willReturn($pinningMode);
    }

    protected function sut(): DestinationPolicyFactory
    {
        return new DestinationPolicyFactory($this->moduleConfigMock, $this->loggerServiceMock);
    }

    public function testBuildsAPolicy(): void
    {
        $this->assertInstanceOf(DestinationPolicy::class, $this->sut()->build());
    }

    public function testPassesThroughTheConfiguredPinningMode(): void
    {
        $this->configure(pinningMode: AddressPinningModeEnum::Required);

        $this->assertSame(AddressPinningModeEnum::Required, $this->sut()->build()->getAddressPinningMode());
    }

    public function testPassesThroughAllowedHosts(): void
    {
        $this->configure(allowedHosts: ['rp.internal.example']);

        $policy = $this->sut()->build();

        $this->assertTrue($policy->isUriAllowed('https://rp.internal.example/jwks'));
    }

    /**
     * The narrow range is the point of the option: permitting one internal endpoint must not permit its
     * neighbours.
     */
    public function testPassesThroughAllowedRangesWithoutWideningThem(): void
    {
        $this->configure(allowedCidrs: ['10.1.2.3/32']);

        $policy = $this->sut()->build();

        $this->assertTrue($policy->isAddressAllowed('10.1.2.3'));
        $this->assertFalse($policy->isAddressAllowed('10.1.2.4'));
    }

    public function testRefusesPlainHttpUnlessConfiguredToAllowIt(): void
    {
        $this->configure(allowedHosts: ['rp.internal.example']);

        $this->assertFalse($this->sut()->build()->isUriAllowed('http://rp.internal.example/jwks'));

        $this->configure(allowedSchemes: ['https', 'http'], allowedHosts: ['rp.internal.example']);

        $this->assertTrue($this->sut()->build()->isUriAllowed('http://rp.internal.example/jwks'));
    }

    /**
     * A range that can never match is a configuration mistake that would otherwise look like a working
     * exemption until the day someone relies on it.
     */
    public function testUnusableConfigurationIsRefusedWhenThePolicyIsBuilt(): void
    {
        $this->configure(allowedCidrs: ['not-a-range']);

        $this->expectException(DestinationPolicyException::class);

        $this->sut()->build();
    }
}
