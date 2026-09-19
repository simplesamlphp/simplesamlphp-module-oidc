<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Factories;

use DateInterval;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\SimpleCache\CacheInterface;
use ReflectionProperty;
use SimpleSAML\Module\oidc\Factories\DestinationPolicyFactory;
use SimpleSAML\Module\oidc\Factories\JwksFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\FederationCache;
use SimpleSAML\OpenID\Decorators\CacheDecorator;
use SimpleSAML\OpenID\Decorators\DateIntervalDecorator;
use SimpleSAML\OpenID\Decorators\HttpClientDecorator;
use SimpleSAML\OpenID\Jwks;
use SimpleSAML\OpenID\Network\DestinationPolicy;
use SimpleSAML\OpenID\SupportedAlgorithms;
use SimpleSAML\OpenID\SupportedSerializers;

/**
 * The factory behind the library's Jwks service.
 *
 * `routing/services/services.yml` names `build` as the factory of the `SimpleSAML\OpenID\Jwks` service, which
 * fetches and decorates JWK Sets. What the factory decides is what the library runs with: the configured
 * signature algorithms, the federation cache and the fetched-artifact cache duration, the protocol HTTP client
 * options, the destination policy for the fetches, and the module's logger. The timestamp validation leeway
 * is not among them: it stays at the library's default, as it does for the VerifiableCredentials service,
 * pinned as it stands and queued as a production fix.
 *
 * The policy is taken as its factory rather than built, and not built until a Jwks is, for the reason
 * FederationFactory gives: building it throws on a malformed configuration, and the container reaches this
 * factory while wiring up the admin screens which exist to report such an option. The Jwks keeps most of
 * what it was built with to itself, so the tests read it back by reflection where it has no accessor; the
 * HTTP client options are read back as the request timeout the library's client decorator derives from them.
 */
#[CoversClass(JwksFactory::class)]
#[AllowMockObjectsWithoutExpectations]
class JwksFactoryTest extends TestCase
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

    protected DateInterval $maxCacheDuration;

    protected DestinationPolicy $destinationPolicy;


    protected function setUp(): void
    {
        $this->supportedAlgorithms = new SupportedAlgorithms();
        $this->maxCacheDuration = new DateInterval('PT7H');
        $this->destinationPolicy = new DestinationPolicy();

        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getSupportedAlgorithms')->willReturn($this->supportedAlgorithms);
        $this->moduleConfigMock->method('getFederationCacheMaxDurationForFetched')
            ->willReturn($this->maxCacheDuration);
        $this->moduleConfigMock->method('getProtocolHttpClientOptions')
            ->willReturn(['timeout' => self::REQUEST_TIMEOUT]);

        $this->loggerServiceMock = $this->createMock(LoggerService::class);

        $this->destinationPolicyFactoryMock = $this->createMock(DestinationPolicyFactory::class);
        $this->destinationPolicyFactoryMock->method('build')->willReturn($this->destinationPolicy);
    }


    protected function sut(?FederationCache $federationCache = null): JwksFactory
    {
        return new JwksFactory(
            $this->moduleConfigMock,
            $this->loggerServiceMock,
            $this->destinationPolicyFactoryMock,
            $federationCache,
        );
    }


    protected function propertyOf(Jwks $jwks, string $property): mixed
    {
        return (new ReflectionProperty($jwks, $property))->getValue($jwks);
    }


    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(JwksFactory::class, $this->sut());
    }


    /**
     * The configured algorithms and cache duration are handed over as the very objects, the duration wrapped
     * in the library's decorator; the HTTP client options reach the client the library builds; the
     * destination policy is the one its factory builds; the logger is the module's; the serializers are
     * what a bare Jwks has.
     */
    public function testBuildsTheJwksAroundTheConfiguredValuesThePolicyAndTheLogger(): void
    {
        $jwks = $this->sut()->build();

        $this->assertSame($this->supportedAlgorithms, $this->propertyOf($jwks, 'supportedAlgorithms'));
        $maxCacheDurationDecorator = $this->propertyOf($jwks, 'maxCacheDurationDecorator');
        $this->assertInstanceOf(DateIntervalDecorator::class, $maxCacheDurationDecorator);
        $this->assertSame($this->maxCacheDuration, $maxCacheDurationDecorator->dateInterval);
        $httpClientDecorator = $this->propertyOf($jwks, 'httpClientDecorator');
        $this->assertInstanceOf(HttpClientDecorator::class, $httpClientDecorator);
        $this->assertSame(self::REQUEST_TIMEOUT, $httpClientDecorator->getRequestTimeout());
        $this->assertSame($this->destinationPolicy, $jwks->destinationPolicy());
        $this->assertSame($this->loggerServiceMock, $this->propertyOf($jwks, 'logger'));
        $this->assertEquals(new SupportedSerializers(), $this->propertyOf($jwks, 'supportedSerializers'));
    }


    /**
     * The federation cache is optional, and when there is one the Jwks caches in the very cache behind it.
     */
    public function testGivesTheJwksTheFederationCacheWhenThereIsOne(): void
    {
        $cache = $this->createMock(CacheInterface::class);

        $jwks = $this->sut(new FederationCache($cache))->build();

        $cacheDecorator = $this->propertyOf($jwks, 'cacheDecorator');
        $this->assertInstanceOf(CacheDecorator::class, $cacheDecorator);
        $this->assertSame($cache, $cacheDecorator->cache);
    }


    public function testLeavesTheJwksWithoutACacheWhenThereIsNoFederationCache(): void
    {
        $jwks = $this->sut()->build();

        $this->assertNull($this->propertyOf($jwks, 'cacheDecorator'));
    }


    /**
     * The configured leeway is not so much as read, and the Jwks runs with the leeway a bare one has. Pinned
     * as the present behaviour; the fix is to hand it over as the Federation and Jws factories do.
     */
    public function testLeavesTheTimestampValidationLeewayAtTheLibrarysDefault(): void
    {
        $this->moduleConfigMock->expects($this->never())->method('getTimestampValidationLeeway');

        $jwks = $this->sut()->build();

        $this->assertEquals($this->leewayOf(new Jwks()), $this->leewayOf($jwks));
    }


    protected function leewayOf(Jwks $jwks): DateInterval
    {
        $leewayDecorator = $this->propertyOf($jwks, 'timestampValidationLeewayDecorator');
        $this->assertInstanceOf(DateIntervalDecorator::class, $leewayDecorator);

        return $leewayDecorator->dateInterval;
    }


    /**
     * The policy may not be built until a Jwks is; see the class comment.
     */
    public function testDoesNotBuildTheDestinationPolicyUntilItBuilds(): void
    {
        $destinationPolicyFactory = $this->createMock(DestinationPolicyFactory::class);
        $destinationPolicyFactory->expects($this->never())->method('build');

        new JwksFactory($this->moduleConfigMock, $this->loggerServiceMock, $destinationPolicyFactory);
    }
}
