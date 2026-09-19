<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Factories;

use DateInterval;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;
use SimpleSAML\Module\oidc\Factories\DestinationPolicyFactory;
use SimpleSAML\Module\oidc\Factories\TokenStatusListFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Network\DestinationPolicy;
use SimpleSAML\OpenID\SupportedAlgorithms;
use SimpleSAML\OpenID\SupportedSerializers;
use SimpleSAML\OpenID\TokenStatusList;

/**
 * The factory behind the library's TokenStatusList service.
 *
 * `routing/services/services.yml` names `build` as the factory of the `SimpleSAML\OpenID\TokenStatusList`
 * service, whose status list, status list token and status reference factories the module builds its own
 * status lists with; it fetches none. What the factory decides is what the library runs with: the configured
 * signature algorithms and timestamp validation leeway, the destination policy for fetches, and the module's
 * logger. No cache, cache duration or HTTP client options are handed over, which the module's use of the
 * service never reaches.
 *
 * The policy is taken as its factory rather than built, and not built until a TokenStatusList is, for the
 * reason FederationFactory gives: building it throws on a malformed configuration, and the container reaches
 * this factory while wiring up the admin screens which exist to report such an option. The tests read the
 * built service back through its accessors where it has them and by reflection where it does not.
 */
#[CoversClass(TokenStatusListFactory::class)]
#[AllowMockObjectsWithoutExpectations]
class TokenStatusListFactoryTest extends TestCase
{
    protected MockObject $moduleConfigMock;

    protected MockObject $loggerServiceMock;

    protected MockObject $destinationPolicyFactoryMock;

    protected SupportedAlgorithms $supportedAlgorithms;

    protected DateInterval $timestampValidationLeeway;

    protected DestinationPolicy $destinationPolicy;


    protected function setUp(): void
    {
        $this->supportedAlgorithms = new SupportedAlgorithms();
        $this->timestampValidationLeeway = new DateInterval('PT3M');
        $this->destinationPolicy = new DestinationPolicy();

        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getSupportedAlgorithms')->willReturn($this->supportedAlgorithms);
        $this->moduleConfigMock->method('getTimestampValidationLeeway')
            ->willReturn($this->timestampValidationLeeway);

        $this->loggerServiceMock = $this->createMock(LoggerService::class);

        $this->destinationPolicyFactoryMock = $this->createMock(DestinationPolicyFactory::class);
        $this->destinationPolicyFactoryMock->method('build')->willReturn($this->destinationPolicy);
    }


    protected function sut(): TokenStatusListFactory
    {
        return new TokenStatusListFactory(
            $this->moduleConfigMock,
            $this->loggerServiceMock,
            $this->destinationPolicyFactoryMock,
        );
    }


    protected function propertyOf(TokenStatusList $tokenStatusList, string $property): mixed
    {
        return (new ReflectionProperty($tokenStatusList, $property))->getValue($tokenStatusList);
    }


    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(TokenStatusListFactory::class, $this->sut());
    }


    /**
     * The configured algorithms and leeway are handed over as the very objects, the leeway wrapped in the
     * library's decorator; the destination policy is the one its factory builds; the logger is the module's;
     * there is no cache, and the cache duration and the serializers are what a bare TokenStatusList has.
     */
    public function testBuildsTheTokenStatusListAroundTheConfiguredValuesThePolicyAndTheLogger(): void
    {
        $tokenStatusList = $this->sut()->build();

        $this->assertSame($this->supportedAlgorithms, $this->propertyOf($tokenStatusList, 'supportedAlgorithms'));
        $this->assertSame(
            $this->timestampValidationLeeway,
            $tokenStatusList->timestampValidationLeewayDecorator()->dateInterval,
        );
        $this->assertSame($this->destinationPolicy, $tokenStatusList->destinationPolicy());
        $this->assertSame($this->loggerServiceMock, $this->propertyOf($tokenStatusList, 'logger'));
        $this->assertNull($tokenStatusList->cacheDecorator());
        $this->assertEquals(
            (new TokenStatusList())->maxCacheDurationDecorator()->dateInterval,
            $tokenStatusList->maxCacheDurationDecorator()->dateInterval,
        );
        $this->assertEquals(
            new SupportedSerializers(),
            $this->propertyOf($tokenStatusList, 'supportedSerializers'),
        );
    }


    /**
     * The policy may not be built until a TokenStatusList is; see the class comment.
     */
    public function testDoesNotBuildTheDestinationPolicyUntilItBuilds(): void
    {
        $destinationPolicyFactory = $this->createMock(DestinationPolicyFactory::class);
        $destinationPolicyFactory->expects($this->never())->method('build');

        new TokenStatusListFactory($this->moduleConfigMock, $this->loggerServiceMock, $destinationPolicyFactory);
    }
}
