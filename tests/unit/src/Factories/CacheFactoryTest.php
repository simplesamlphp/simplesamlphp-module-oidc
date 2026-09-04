<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Factories;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Exceptions\OidcException;
use SimpleSAML\Module\oidc\Factories\CacheFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\ClassInstanceBuilder;
use SimpleSAML\Module\oidc\Utils\VciCache;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

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
     * No adapter configured means no VCI caching, not a broken container.
     */
    public function testForVciReturnsNullWhenNoAdapterIsConfigured(): void
    {
        $this->moduleConfigMock->method('getVciCacheAdapterClass')->willReturn(null);
        $this->classInstanceBuilderMock->expects($this->never())->method('build');

        $this->assertNull($this->sut()->forVci());
    }


    public function testForVciBuildsTheConfiguredAdapter(): void
    {
        $this->moduleConfigMock->method('getVciCacheAdapterClass')->willReturn(ArrayAdapter::class);
        $this->moduleConfigMock->method('getVciCacheAdapterArguments')->willReturn(['argument']);

        $this->classInstanceBuilderMock->expects($this->once())
            ->method('build')
            ->with(ArrayAdapter::class, ['argument'])
            ->willReturn(new ArrayAdapter());

        $this->assertInstanceOf(VciCache::class, $this->sut()->forVci());
    }


    /**
     * A class which is not a cache adapter must be refused rather than reaching a caller which will
     * only find out when it tries to cache something.
     */
    public function testForVciRefusesAnAdapterOfTheWrongType(): void
    {
        $this->moduleConfigMock->method('getVciCacheAdapterClass')->willReturn(self::class);
        $this->moduleConfigMock->method('getVciCacheAdapterArguments')->willReturn([]);

        $this->classInstanceBuilderMock->method('build')->willReturn($this);

        $this->expectException(OidcException::class);

        $this->sut()->forVci();
    }


    /**
     * An adapter which cannot be constructed - wrong arguments, an unreachable server - must be
     * reported rather than surfacing as whatever the adapter itself threw.
     */
    public function testForVciReportsAnAdapterWhichCannotBeBuilt(): void
    {
        $this->moduleConfigMock->method('getVciCacheAdapterClass')->willReturn(ArrayAdapter::class);
        $this->moduleConfigMock->method('getVciCacheAdapterArguments')->willReturn([]);

        $this->classInstanceBuilderMock->method('build')
            ->willThrowException(new OidcException('Adapter constructor said no.'));

        $this->loggerServiceMock->expects($this->once())->method('error');

        $this->expectException(OidcException::class);

        $this->sut()->forVci();
    }
}
