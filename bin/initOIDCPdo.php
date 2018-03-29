#!/usr/bin/env php
<?php

use SimpleSAML\Modules\OpenIDConnect\Services\DatabaseMigration;

const OIDC_DATABASE_VERSION = '20180305180300';

$dir = realpath(dirname(getcwd().'/'.$_SERVER['SCRIPT_FILENAME']));
var_dump($dir);
while ($dir) {
    if (file_exists("{$dir}/vendor/autoload.php")) {
        require_once "{$dir}/vendor/autoload.php";
        break;
    }

    $dir = mb_substr($dir, 0, mb_strrpos($dir, DIRECTORY_SEPARATOR));
}

if (!class_exists(\SimpleSAML\Database::class)) {
    echo 'Autoloading not found';
    exit(1);
}

(new DatabaseMigration())->migrate();
