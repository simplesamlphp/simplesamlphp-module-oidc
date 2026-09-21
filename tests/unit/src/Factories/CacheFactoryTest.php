<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Factories;

use Closure;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Exceptions\OidcException;
use SimpleSAML\Module\oidc\Factories\CacheFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\ClassInstanceBuilder;
use SimpleSAML\Module\oidc\Utils\FederationCache;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;
use SimpleSAML\Module\oidc\Utils\VciCache;
use stdClass;
use Symfony\Component\Cache\Adapter\AdapterInterface;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

/**
 * The three caches are built the same way from three pairs of configuration options, so every test here
 * runs once per cache: a cache is only as configured as its own pair says, and a mistake in one of the
 * three methods would otherwise hide behind the tests of the other two.
 */
#[CoversClass(CacheFactory::class)]
#[AllowMockObjectsWithoutExpectations]
class CacheFactoryTest extends TestCase
{
    protected MockObject $moduleConfigMock;

    protected MockObject $loggerServiceMock;

    protected MockObject $classInstanceBuilderMock;


    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        $this->classInstanceBuilderMock = $this->createMock(ClassInstanceBuilder::class);
    }


    protected function sut(): CacheFactory
    {
        return new CacheFactory(
            $this->moduleConfigMock,
            $this->loggerServiceMock,
            $this->classInstanceBuilderMock,
        );
    }


    /**
     * Each cache with the two configuration options it is built from and the class it comes back as.
     *
     * @return array<string, array{0: \Closure, 1: string, 2: string, 3: class-string}>
     */
    public static function cacheProvider(): array
    {
        return [
            'federation' => [
                fn(CacheFactory $factory): ?FederationCache => $factory->forFederation(),
                'getFederationCacheAdapterClass',
                'getFederationCacheAdapterArguments',
                FederationCache::class,
            ],
            'VCI' => [
                fn(CacheFactory $factory): ?VciCache => $factory->forVci(),
                'getVciCacheAdapterClass',
                'getVciCacheAdapterArguments',
                VciCache::class,
            ],
            'protocol' => [
                fn(CacheFactory $factory): ?ProtocolCache => $factory->forProtocol(),
                'getProtocolCacheAdapterClass',
                'getProtocolCacheAdapterArguments',
                ProtocolCache::class,
            ],
        ];
    }


    /**
     * The same three caches without the class they come back as, for the tests where none is built.
     *
     * @return array<string, array{0: \Closure, 1: string, 2: string}>
     */
    public static function cacheSourceProvider(): array
    {
        return array_map(fn(array $case): array => array_slice($case, 0, 3), self::cacheProvider());
    }


    /**
     * No adapter configured means no caching, not a broken container.
     */
    #[DataProvider('cacheSourceProvider')]
    public function testReturnsNullWhenNoAdapterIsConfigured(
        Closure $build,
        string $classGetter,
        string $argumentsGetter,
    ): void {
        $this->moduleConfigMock->method($classGetter)->willReturn(null);
        $this->moduleConfigMock->expects($this->never())->method($argumentsGetter);
        $this->classInstanceBuilderMock->expects($this->never())->method('build');
        $this->loggerServiceMock->expects($this->never())->method($this->anything());

        $this->assertNull($build($this->sut()));
    }


    #[DataProvider('cacheProvider')]
    public function testBuildsTheConfiguredAdapter(
        Closure $build,
        string $classGetter,
        string $argumentsGetter,
        string $cacheClass,
    ): void {
        $this->moduleConfigMock->method($classGetter)->willReturn(ArrayAdapter::class);
        $this->moduleConfigMock->method($argumentsGetter)->willReturn(['argument']);

        $this->classInstanceBuilderMock->expects($this->once())
            ->method('build')
            ->with(ArrayAdapter::class, ['argument'])
            ->willReturn(new ArrayAdapter());

        $this->assertInstanceOf($cacheClass, $build($this->sut()));
    }


    /**
     * A class which is not a cache adapter must be refused rather than reaching a caller which will
     * only find out when it tries to cache something.
     */
    #[DataProvider('cacheSourceProvider')]
    public function testRefusesAnAdapterOfTheWrongType(
        Closure $build,
        string $classGetter,
        string $argumentsGetter,
    ): void {
        $this->moduleConfigMock->method($classGetter)->willReturn(stdClass::class);
        $this->moduleConfigMock->method($argumentsGetter)->willReturn([]);

        $this->classInstanceBuilderMock->method('build')->willReturn(new stdClass());

        $message = 'Unexpected cache adapter class: stdClass. Expected type: ' . AdapterInterface::class;
        $this->loggerServiceMock->expects($this->once())->method('error')->with($message);

        $this->expectException(OidcException::class);
        $this->expectExceptionMessage($message);

        $build($this->sut());
    }


    /**
     * An adapter which cannot be constructed - wrong arguments, an unreachable server - must be
     * reported rather than surfacing as whatever the adapter itself threw.
     */
    #[DataProvider('cacheSourceProvider')]
    public function testReportsAnAdapterWhichCannotBeBuilt(
        Closure $build,
        string $classGetter,
        string $argumentsGetter,
    ): void {
        $this->moduleConfigMock->method($classGetter)->willReturn(ArrayAdapter::class);
        $this->moduleConfigMock->method($argumentsGetter)->willReturn([]);

        $this->classInstanceBuilderMock->method('build')
            ->willThrowException(new OidcException('Adapter constructor said no.'));

        $message = 'Error building cache adapter instance: Adapter constructor said no.';
        $this->loggerServiceMock->expects($this->once())->method('error')->with($message);

        $this->expectException(OidcException::class);
        $this->expectExceptionMessage($message);

        $build($this->sut());
    }
}
