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

    /**
     * The ceiling is SQLite's pre 3.32 default of 999, which is the lowest of the three drivers and so
     * the one every statement has to be built to.
     */
    public function testWorksOutHowManyRowsOneStatementCanName(): void
    {
        $this->assertSame(999, $this->rowsPerStatement(1));
        $this->assertSame(499, $this->rowsPerStatement(2));
        $this->assertSame(333, $this->rowsPerStatement(3));
    }

    public function testCountsWhatTheStatementBindsBesidesItsRows(): void
    {
        // A statement carrying a timestamp of its own has one fewer variable to spend on rows, and at
        // two per row that costs a whole row rather than half of one.
        $this->assertSame(499, $this->rowsPerStatement(2, 1));
        $this->assertSame(498, $this->rowsPerStatement(2, 3));
    }

    /**
     * A statement can not name a fraction of a row, and answering zero would leave a caller chunking by
     * nothing, which never advances.
     */
    public function testNamesAtLeastOneRowHoweverWideTheRowIs(): void
    {
        $this->assertSame(1, $this->rowsPerStatement(1000));
        $this->assertSame(1, $this->rowsPerStatement(2, 999));
    }

    protected function rowsPerStatement(int $perRow, int $fixed = 0): int
    {
        return (new class (
            $this->createMock(ModuleConfig::class),
            $this->createMock(Database::class),
            $this->createMock(ProtocolCache::class),
        ) extends AbstractDatabaseRepository {
            public function getTableName(): ?string
            {
                return 'sut';
            }

            public function rows(int $perRow, int $fixed): int
            {
                return $this->maxRowsPerStatement($perRow, $fixed);
            }
        })->rows($perRow, $fixed);
    }
}
