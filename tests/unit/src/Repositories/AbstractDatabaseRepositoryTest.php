<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Repositories;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AbstractDatabaseRepository;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;

#[CoversClass(AbstractDatabaseRepository::class)]
class AbstractDatabaseRepositoryTest extends TestCase
{
    protected MockObject $moduleConfigMock;
    protected MockObject $databaseMock;
    protected MockObject $protocolCacheMock;

    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->databaseMock = $this->createMock(Database::class);
        $this->protocolCacheMock = $this->createMock(ProtocolCache::class);
    }

    protected function sut(
        ?ModuleConfig $moduleConfig = null,
        ?Database $database = null,
        ?ProtocolCache $protocolCache = null,
    ): AbstractDatabaseRepository {
        $moduleConfig ??= $this->moduleConfigMock;
        $database ??= $this->databaseMock;
        $protocolCache ??= $this->protocolCacheMock;

        return new class ($moduleConfig, $database, $protocolCache) extends AbstractDatabaseRepository
        {
            public function getTableName(): ?string
            {
                return 'sut';
            }
        };
    }

    public function testCanGetCacheKey(): void
    {
        $this->assertSame('sut_something', $this->sut()->getCacheKey('something'));
    }
}
