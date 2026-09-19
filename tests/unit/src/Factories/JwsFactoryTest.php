<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Factories;

use DateInterval;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;
use SimpleSAML\Module\oidc\Factories\JwsFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Decorators\DateIntervalDecorator;
use SimpleSAML\OpenID\Jws;
use SimpleSAML\OpenID\SupportedAlgorithms;
use SimpleSAML\OpenID\SupportedSerializers;

/**
 * The factory behind the library's Jws service.
 *
 * `routing/services/services.yml` names `build` as the factory of the `SimpleSAML\OpenID\Jws` service, which
 * the bearer token validator and the nonce service parse tokens with. What the factory decides is what the
 * library runs with: the configured signature algorithms, serializers and timestamp validation leeway, and
 * the module's logger. The Jws keeps all of it to itself, so the tests read it back by reflection.
 */
#[CoversClass(JwsFactory::class)]
#[AllowMockObjectsWithoutExpectations]
class JwsFactoryTest extends TestCase
{
    protected MockObject $moduleConfigMock;

    protected MockObject $loggerServiceMock;

    protected SupportedAlgorithms $supportedAlgorithms;

    protected SupportedSerializers $supportedSerializers;

    protected DateInterval $timestampValidationLeeway;


    protected function setUp(): void
    {
        $this->supportedAlgorithms = new SupportedAlgorithms();
        $this->supportedSerializers = new SupportedSerializers();
        $this->timestampValidationLeeway = new DateInterval('PT3M');

        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getSupportedAlgorithms')->willReturn($this->supportedAlgorithms);
        $this->moduleConfigMock->method('getSupportedSerializers')->willReturn($this->supportedSerializers);
        $this->moduleConfigMock->method('getTimestampValidationLeeway')
            ->willReturn($this->timestampValidationLeeway);

        $this->loggerServiceMock = $this->createMock(LoggerService::class);
    }


    protected function sut(): JwsFactory
    {
        return new JwsFactory($this->moduleConfigMock, $this->loggerServiceMock);
    }


    protected function propertyOf(Jws $jws, string $property): mixed
    {
        return (new ReflectionProperty($jws, $property))->getValue($jws);
    }


    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(JwsFactory::class, $this->sut());
    }


    /**
     * The configured algorithms, serializers and leeway are handed over as the very objects, the leeway
     * wrapped in the library's decorator, and the logger is the module's.
     */
    public function testBuildsTheJwsAroundTheConfiguredAlgorithmsSerializersAndLeewayAndTheLogger(): void
    {
        $jws = $this->sut()->build();

        $this->assertSame($this->supportedAlgorithms, $this->propertyOf($jws, 'supportedAlgorithms'));
        $this->assertSame($this->supportedSerializers, $this->propertyOf($jws, 'supportedSerializers'));
        $leewayDecorator = $this->propertyOf($jws, 'timestampValidationLeewayDecorator');
        $this->assertInstanceOf(DateIntervalDecorator::class, $leewayDecorator);
        $this->assertSame($this->timestampValidationLeeway, $leewayDecorator->dateInterval);
        $this->assertSame($this->loggerServiceMock, $this->propertyOf($jws, 'logger'));
    }
}
