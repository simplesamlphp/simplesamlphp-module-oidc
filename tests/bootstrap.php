<?php

declare(strict_types=1);

$projectRoot = dirname(__DIR__);
require_once $projectRoot . '/vendor/autoload.php';

// Symlink module into ssp vendor lib so that templates and urls can resolve correctly
$modulesDir = $projectRoot . '/vendor/simplesamlphp/simplesamlphp/modules';
$linkPath = $modulesDir . '/oidc';
$target = '../../../../';

if (!is_dir($modulesDir)) {
    mkdir($modulesDir, 0777, true);
}

if (is_link($linkPath)) {
    if (!file_exists($linkPath) || (readlink($linkPath) !== $target && realpath($linkPath) !== $projectRoot)) {
        unlink($linkPath);
        symlink($target, $linkPath);
        echo "Re-linking '$linkPath' to '$target'\n";
    } else {
        echo "'$linkPath' linked to '$projectRoot'\n";
    }
} elseif (!file_exists($linkPath)) {
    echo "Linking '$linkPath' to '$target'\n";
    symlink($target, $linkPath);
}
