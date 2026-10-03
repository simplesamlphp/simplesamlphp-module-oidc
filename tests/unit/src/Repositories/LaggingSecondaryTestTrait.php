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
        $database = Database::getInstance();
        $emptyStatementMock = $this->createMock(PDOStatement::class);
        $emptyStatementMock->method('fetch')->willReturn(false);
        $emptyStatementMock->method('fetchAll')->willReturn([]);

        $databaseMock = $this->createMock(Database::class);
        $databaseMock->method('applyPrefix')->willReturnCallback($database->applyPrefix(...));
        $databaseMock->method('write')->willReturnCallback($database->write(...));
        $databaseMock->method('readPrimary')->willReturnCallback($database->readPrimary(...));
        $databaseMock->method('read')->willReturn($emptyStatementMock);

        return $databaseMock;
    }
}
