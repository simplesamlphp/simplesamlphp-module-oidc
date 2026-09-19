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
 * factory decides is what the library runs with: the configured signature algorithms and the module's
 * logger. The timestamp validation leeway, which the library hands its credential factories, is not among
 * them: it stays at the library's default, as it does for the Jwks service, while the Core, Jws,
 * RequestObject, TokenStatusList and Federation services get the configured one. That omission is pinned
 * as it stands and queued as a production fix. The service keeps all of it to itself, so the tests read it
 * back by reflection.
 */
#[CoversClass(VerifiableCredentialsFactory::class)]
#[AllowMockObjectsWithoutExpectations]
class VerifiableCredentialsFactoryTest extends TestCase
{
    protected MockObject $moduleConfigMock;

    protected MockObject $loggerServiceMock;

    protected SupportedAlgorithms $supportedAlgorithms;


    protected function setUp(): void
    {
        $this->supportedAlgorithms = new SupportedAlgorithms();

        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getSupportedAlgorithms')->willReturn($this->supportedAlgorithms);

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
     * The configured leeway is not so much as read, and the service runs with the leeway a bare one has.
     * Pinned as the present behaviour; the fix is to hand it over as the other library factories do.
     */
    public function testLeavesTheTimestampValidationLeewayAtTheLibrarysDefault(): void
    {
        $this->moduleConfigMock->expects($this->never())->method('getTimestampValidationLeeway');

        $verifiableCredentials = $this->sut()->build();

        $this->assertEquals(
            $this->leewayOf(new VerifiableCredentials()),
            $this->leewayOf($verifiableCredentials),
        );
    }


    protected function leewayOf(VerifiableCredentials $verifiableCredentials): DateInterval
    {
        $leewayDecorator = $this->propertyOf($verifiableCredentials, 'timestampValidationLeewayDecorator');
        $this->assertInstanceOf(DateIntervalDecorator::class, $leewayDecorator);

        return $leewayDecorator->dateInterval;
    }
}
