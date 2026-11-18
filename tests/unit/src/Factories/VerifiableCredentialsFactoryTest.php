<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Factories;

use DateInterval;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;
use SimpleSAML\Module\oidc\Factories\VerifiableCredentialsFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Decorators\DateIntervalDecorator;
use SimpleSAML\OpenID\SupportedAlgorithms;
use SimpleSAML\OpenID\SupportedSerializers;
use SimpleSAML\OpenID\VerifiableCredentials;

/**
 * The factory behind the library's VerifiableCredentials service.
 *
 * `routing/services/services.yml` names `build` as the factory of the `SimpleSAML\OpenID\VerifiableCredentials`
 * service, the credential offer, credential and transaction code factories of the issuance flow. What the
 * factory decides is what the library runs with: the configured signature algorithms and timestamp validation
 * leeway, which the library hands its credential factories, and the module's logger. The service keeps all of
 * it to itself, so the tests read it back by reflection.
 */
#[CoversClass(VerifiableCredentialsFactory::class)]
#[AllowMockObjectsWithoutExpectations]
class VerifiableCredentialsFactoryTest extends TestCase
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


    protected function sut(): VerifiableCredentialsFactory
    {
        return new VerifiableCredentialsFactory($this->moduleConfigMock, $this->loggerServiceMock);
    }


    protected function propertyOf(VerifiableCredentials $verifiableCredentials, string $property): mixed
    {
        return (new ReflectionProperty($verifiableCredentials, $property))->getValue($verifiableCredentials);
    }


    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(VerifiableCredentialsFactory::class, $this->sut());
    }


    /**
     * The configured algorithms are handed over as the very object, the logger is the module's, and the
     * serializers are what a bare service has.
     */
    public function testBuildsTheServiceAroundTheConfiguredAlgorithmsAndTheLogger(): void
    {
        $verifiableCredentials = $this->sut()->build();

        $this->assertSame(
            $this->supportedAlgorithms,
            $this->propertyOf($verifiableCredentials, 'supportedAlgorithms'),
        );
        $this->assertSame($this->loggerServiceMock, $this->propertyOf($verifiableCredentials, 'logger'));
        $this->assertEquals(
            new SupportedSerializers(),
            $this->propertyOf($verifiableCredentials, 'supportedSerializers'),
        );
    }


    /**
     * The configured leeway is handed over as the very object, as the other library factories hand theirs; it
     * is not the library's default of a minute.
     */
    public function testHandsOverTheConfiguredTimestampValidationLeeway(): void
    {
        $this->assertSame($this->timestampValidationLeeway, $this->leewayOf($this->sut()->build()));
    }


    protected function leewayOf(VerifiableCredentials $verifiableCredentials): DateInterval
    {
        $leewayDecorator = $this->propertyOf($verifiableCredentials, 'timestampValidationLeewayDecorator');
        $this->assertInstanceOf(DateIntervalDecorator::class, $leewayDecorator);

        return $leewayDecorator->dateInterval;
    }
}
