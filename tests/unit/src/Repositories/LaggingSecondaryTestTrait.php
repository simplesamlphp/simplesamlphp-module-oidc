<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Repositories;

use PDOStatement;
use SimpleSAML\Database;

/**
 * For repositories which read back what was written moments earlier, and so must not ask a database secondary.
 */
trait LaggingSecondaryTestTrait
{
    /**
     * A deployment whose database secondary has not caught up yet: writes and primary reads reach the test
     * database, while a read from the secondary finds nothing.
     */
    protected function databaseWithALaggingSecondary(): Database
    {
        return $this->databaseWithAStaleSecondary([]);
    }


    /**
     * A deployment whose database secondary has not caught up with a write yet: writes and primary reads reach the
     * test database, while a read from the secondary answers with the rows given, as they were before that write.
     */
    protected function databaseWithAStaleSecondary(array $staleRows): Database
    {
        $database = Database::getInstance();

        $databaseMock = $this->createMock(Database::class);
        $databaseMock->method('applyPrefix')->willReturnCallback($database->applyPrefix(...));
        $databaseMock->method('write')->willReturnCallback($database->write(...));
        $databaseMock->method('readPrimary')->willReturnCallback($database->readPrimary(...));
        $databaseMock->method('read')->willReturnCallback(function () use ($staleRows): PDOStatement {
            $rows = $staleRows;
            $statementMock = $this->createMock(PDOStatement::class);
            $statementMock->method('fetch')->willReturnCallback(function () use (&$rows): mixed {
                return array_shift($rows) ?? false;
            });
            $statementMock->method('fetchAll')->willReturn($staleRows);

            return $statementMock;
        });

        return $databaseMock;
    }


    /**
     * The rows of a table with this ID as they are now, for a stale secondary to answer with after a later write.
     */
    protected function rowsWithId(string $table, string $id): array
    {
        return Database::getInstance()
            ->readPrimary("SELECT * FROM $table WHERE id = :id", ['id' => $id])
            ->fetchAll();
    }
}
