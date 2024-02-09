#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * Script which can be run to do the module installation which includes running database migrations.
 */

use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;

// This is the base directory of the SimpleSAMLphp installation
$baseDir = dirname(__FILE__, 4);

// Add library autoloader and configuration
require_once $baseDir . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . '_autoload.php';

echo 'Starting with module installation.' . PHP_EOL;

try {
    $database = Database::getInstance();
    $databaseMigration = new DatabaseMigration($database);

    if ($databaseMigration->isUpdated()) {
        echo 'Database is up to date, skipping.' . PHP_EOL;
        return 0;
    }

    echo 'Running database migrations.' . PHP_EOL;

    $databaseMigration->migrate();

    echo 'Done running migrations.';
    return 0;
} catch (Throwable $exception) {
    echo 'There was an error while trying run database migrations: ' . $exception->getMessage();
    return 1;
}
