<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * Copyright (C) 2018 by the Spanish Research and Academic Network.
 *
 * This code was developed by Universidad de Córdoba (UCO https://www.uco.es)
 * for the RedIRIS SIR service (SIR: http://www.rediris.es/sir)
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

$projectRoot = dirname(__DIR__);
require_once $projectRoot . '/vendor/autoload.php';

// Symlink module into ssp vendor lib so that templates and urls can resolve correctly
$linkPath = $projectRoot . '/vendor/simplesamlphp/simplesamlphp/modules/oidc';
if (false === file_exists($linkPath)) {
    echo "Linking '$linkPath' to '$projectRoot'\n";
    symlink($projectRoot, $linkPath);
}
