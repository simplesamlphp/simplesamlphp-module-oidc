#!/usr/bin/env php
<?php

use SimpleSAML\Modules\OpenIDConnect\Services\DatabaseMigration;

const OIDC_DATABASE_VERSION = '20180305180300';

$dir = realpath(dirname(getcwd().'/'.$_SERVER['SCRIPT_FILENAME']));
while ($dir) {
    if (file_exists("{$dir}/lib/_autoload.php")) {
        require_once "{$dir}/lib/_autoload.php";
        break;
    }

    $dir = mb_substr($dir, 0, mb_strrpos($dir, DIRECTORY_SEPARATOR));
}

if (!class_exists(\SimpleSAML\Database::class)) {
    echo 'Autoloading not found';
    exit(1);
}

(new DatabaseMigration())->migrate();
