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

use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\AuthCodeRepository;
use SimpleSAML\Module\oidc\Repositories\RefreshTokenRepository;

/**
 * @param array &$croninfo
 *
 * @return void
 */
function oidc_hook_cron(&$croninfo)
{
    assert('is_array($croninfo)');
    assert('array_key_exists("summary", $croninfo)');
    assert('array_key_exists("tag", $croninfo)');

    $oidcConfig = \SimpleSAML\Configuration::getConfig('module_oidc.php');

    if (null === $oidcConfig->getOptionalValue('cron_tag', null)) {
        return;
    }
    if ($oidcConfig->getOptionalValue('cron_tag', null) !== $croninfo['tag']) {
        return;
    }

    $container = new \SimpleSAML\Module\oidc\Services\Container();

    try {
        $accessTokenRepository = $container->get(AccessTokenRepository::class);
        $accessTokenRepository->removeExpired();

        $authTokenRepository = $container->get(AuthCodeRepository::class);
        $authTokenRepository->removeExpired();

        $refreshTokenRepository = $container->get(RefreshTokenRepository::class);
        $refreshTokenRepository->removeExpired();

        $croninfo['summary'][] = 'Module `oidc` clean up. Removed expired entries from storage.';
    } catch (Exception $e) {
        $message = 'Module `oidc` clean up cron script failed: ' . $e->getMessage();
        \SimpleSAML\Logger::warning($message);
        $croninfo['summary'][] = $message;
    }
}
