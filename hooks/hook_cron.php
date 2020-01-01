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

    if (null === $oidcConfig->getValue('cron_tag', 'hourly')) {
        return;
    }
    if ($oidcConfig->getValue('cron_tag', null) !== $croninfo['tag']) {
        return;
    }

    $container = new \SimpleSAML\Modules\OpenIDConnect\Services\Container();

    try {
        $accessTokenRepository = $container->get(\SimpleSAML\Modules\OpenIDConnect\Repositories\AccessTokenRepository::class);
        $accessTokenRepository->removeExpired();

        $authTokenRepository = $container->get(\SimpleSAML\Modules\OpenIDConnect\Repositories\AuthCodeRepository::class);
        $authTokenRepository->removeExpired();

        $refreshTokenRepository = $container->get(\SimpleSAML\Modules\OpenIDConnect\Repositories\RefreshTokenRepository::class);
        $refreshTokenRepository->removeExpired();

        $croninfo['summary'][] = 'Module `oidc` clean up. Removed expired entries from storage.';
    } catch (Exception $e) {
        $message = 'Module `oidc` clean up cron script failed: '.$e->getMessage();
        \SimpleSAML\Logger::warning($message);
        $croninfo['summary'][] = $message;
    }
}
