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
use SimpleSAML\Module\oidc\Factories\RequestObjectFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Decorators\HttpClientDecorator;
use SimpleSAML\OpenID\Network\DestinationPolicy;
use SimpleSAML\OpenID\RequestObject;
use SimpleSAML\OpenID\SupportedAlgorithms;
use SimpleSAML\OpenID\SupportedSerializers;

/**
 * The factory behind the library's RequestObject service.
 *
 * `routing/services/services.yml` names `build` as the factory of the `SimpleSAML\OpenID\RequestObject`
 * service, which parses Request Objects and fetches the ones a `request_uri` names. What the factory decides
 * is what the library runs with: the configured signature algorithms and timestamp validation leeway, the
 * protocol HTTP client options, the destination policy for the fetches, and the module's logger. No cache is
 * handed over, so a fetched Request Object is not kept.
 *
 * The policy is taken as its factory rather than built, and not built until a RequestObject is, for the
 * reason FederationFactory gives: building it throws on a malformed configuration, and the container reaches
 * this factory while wiring up the admin screens which exist to report such an option. The tests read the
 * built service back through its accessors where it has them and by reflection where it does not; the HTTP
 * client options are read back as the request timeout the library's client decorator derives from them.
 */
#[CoversClass(RequestObjectFactory::class)]
#[AllowMockObjectsWithoutExpectations]
class RequestObjectFactoryTest extends TestCase
{
    /**
     * Distinct from the library's default of five seconds, so a value which never reached the client would show,
     * and positive, since the library warns about a timeout which is not.
     */
    protected const float REQUEST_TIMEOUT = 2.5;


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
        $this->moduleConfigMock->method('getProtocolHttpClientOptions')
            ->willReturn(['timeout' => self::REQUEST_TIMEOUT]);

        $this->loggerServiceMock = $this->createMock(LoggerService::class);

        $this->destinationPolicyFactoryMock = $this->createMock(DestinationPolicyFactory::class);
        $this->destinationPolicyFactoryMock->method('build')->willReturn($this->destinationPolicy);
    }


    protected function sut(): RequestObjectFactory
    {
        return new RequestObjectFactory(
            $this->moduleConfigMock,
            $this->loggerServiceMock,
            $this->destinationPolicyFactoryMock,
        );
    }


    protected function propertyOf(RequestObject $requestObject, string $property): mixed
    {
        return (new ReflectionProperty($requestObject, $property))->getValue($requestObject);
    }


    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(RequestObjectFactory::class, $this->sut());
    }


    /**
     * The configured algorithms and leeway are handed over as the very objects, the leeway wrapped in the
     * library's decorator; the HTTP client options reach the client the library builds; the destination
     * policy is the one its factory builds; the logger is the module's; there is no cache; the serializers
     * are what a bare RequestObject has.
     */
    public function testBuildsTheRequestObjectAroundTheConfiguredValuesThePolicyAndTheLogger(): void
    {
        $requestObject = $this->sut()->build();

        $this->assertSame($this->supportedAlgorithms, $this->propertyOf($requestObject, 'supportedAlgorithms'));
        $this->assertSame(
            $this->timestampValidationLeeway,
            $requestObject->timestampValidationLeewayDecorator()->dateInterval,
        );
        $httpClientDecorator = $this->propertyOf($requestObject, 'httpClientDecorator');
        $this->assertInstanceOf(HttpClientDecorator::class, $httpClientDecorator);
        $this->assertSame(self::REQUEST_TIMEOUT, $httpClientDecorator->getRequestTimeout());
        $this->assertSame($this->destinationPolicy, $requestObject->destinationPolicy());
        $this->assertSame($this->loggerServiceMock, $this->propertyOf($requestObject, 'logger'));
        $this->assertNull($requestObject->cacheDecorator());
        $this->assertEquals(
            new SupportedSerializers(),
            $this->propertyOf($requestObject, 'supportedSerializers'),
        );
    }


    /**
     * The policy may not be built until a RequestObject is; see the class comment.
     */
    public function testDoesNotBuildTheDestinationPolicyUntilItBuilds(): void
    {
        $destinationPolicyFactory = $this->createMock(DestinationPolicyFactory::class);
        $destinationPolicyFactory->expects($this->never())->method('build');

        new RequestObjectFactory($this->moduleConfigMock, $this->loggerServiceMock, $destinationPolicyFactory);
    }
}
