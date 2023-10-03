<?php

declare(strict_types=1);

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

use Psr\Container\ContainerExceptionInterface;
use Psr\Container\NotFoundExceptionInterface;
use SimpleSAML\Logger;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\AuthCodeRepository;
use SimpleSAML\Module\oidc\Repositories\RefreshTokenRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\Container;

/**
 * @param array $croninfo
 * @throws OidcServerException
 * @throws ContainerExceptionInterface
 * @throws NotFoundExceptionInterface
 * @throws Exception
 */
function oidc_hook_cron(array &$croninfo): void
{
    if (
        !array_key_exists('summary', $croninfo) ||
        !is_array($croninfo['summary'])
    ) {
        $croninfo['summary'] = [];
    }
    if (!array_key_exists('tag', $croninfo)) {
        throw OidcServerException::serverError('Invalid croninfo data: missing tag');
    }

    $oidcConfig = (new ModuleConfig())->config();

    if (null === $oidcConfig->getOptionalValue(ModuleConfig::OPTION_CRON_TAG, null)) {
        return;
    }
    if ($oidcConfig->getOptionalValue(ModuleConfig::OPTION_CRON_TAG, null) !== $croninfo['tag']) {
        return;
    }

    $container = new Container();

    try {
        /** @var AccessTokenRepository $accessTokenRepository */
        $accessTokenRepository = $container->get(AccessTokenRepository::class);
        $accessTokenRepository->removeExpired();

        /** @var AuthCodeRepository $authTokenRepository */
        $authTokenRepository = $container->get(AuthCodeRepository::class);
        $authTokenRepository->removeExpired();

        /** @var RefreshTokenRepository $refreshTokenRepository */
        $refreshTokenRepository = $container->get(RefreshTokenRepository::class);
        $refreshTokenRepository->removeExpired();

        $croninfo['summary'][] = 'Module `oidc` clean up. Removed expired entries from storage.';
    } catch (Exception $e) {
        $message = 'Module `oidc` clean up cron script failed: ' . $e->getMessage();
        Logger::warning($message);
        $croninfo['summary'][] = $message;
    }
}
