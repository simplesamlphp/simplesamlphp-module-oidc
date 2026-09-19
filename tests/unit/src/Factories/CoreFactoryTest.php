<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Factories;

use DateInterval;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;
use SimpleSAML\Module\oidc\Factories\CoreFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Core;
use SimpleSAML\OpenID\Decorators\DateIntervalDecorator;
use SimpleSAML\OpenID\SupportedAlgorithms;
use SimpleSAML\OpenID\SupportedSerializers;

/**
 * The factory behind the library's Core service.
 *
 * `routing/services/services.yml` names `build` as the factory of the `SimpleSAML\OpenID\Core` service, and
 * LogoutTokenBuilder builds a Core of its own through this factory when it is given none. What the factory
 * decides is what the library runs with: the configured signature algorithms and timestamp validation
 * leeway, and the module's logger. The serializers are left at the library's default, which is the module's
 * own set (compact only). The Core keeps all of it to itself, so the tests read it back by reflection.
 */
#[CoversClass(CoreFactory::class)]
#[AllowMockObjectsWithoutExpectations]
class CoreFactoryTest extends TestCase
{
    protected MockObject $moduleConfigMock;

    protected MockObject $loggerServiceMock;

    protected SupportedAlgorithms $supportedAlgorithms;

    protected DateInterval $timestampValidationLeeway;


    protected function setUp(): void
    {
        $this->supportedAlgorithms = new SupportedAlgorithms();
        $this->timestampValidationLeeway = new DateInterval('PT3M');

        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getSupportedAlgorithms')->willReturn($this->supportedAlgorithms);
        $this->moduleConfigMock->method('getTimestampValidationLeeway')
            ->willReturn($this->timestampValidationLeeway);

        $this->loggerServiceMock = $this->createMock(LoggerService::class);
    }


    protected function sut(): CoreFactory
    {
        return new CoreFactory($this->moduleConfigMock, $this->loggerServiceMock);
    }


    protected function propertyOf(Core $core, string $property): mixed
    {
        return (new ReflectionProperty($core, $property))->getValue($core);
    }


    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(CoreFactory::class, $this->sut());
    }


    /**
     * The configured algorithms and leeway are handed over as the very objects, the leeway wrapped in the
     * library's decorator, the logger is the module's, and the serializers are what a bare Core has.
     */
    public function testBuildsTheCoreAroundTheConfiguredAlgorithmsAndLeewayAndTheLogger(): void
    {
        $core = $this->sut()->build();

        $this->assertSame($this->supportedAlgorithms, $this->propertyOf($core, 'supportedAlgorithms'));
        $leewayDecorator = $this->propertyOf($core, 'timestampValidationLeewayDecorator');
        $this->assertInstanceOf(DateIntervalDecorator::class, $leewayDecorator);
        $this->assertSame($this->timestampValidationLeeway, $leewayDecorator->dateInterval);
        $this->assertSame($this->loggerServiceMock, $this->propertyOf($core, 'logger'));
        $this->assertEquals(new SupportedSerializers(), $this->propertyOf($core, 'supportedSerializers'));
    }
}
