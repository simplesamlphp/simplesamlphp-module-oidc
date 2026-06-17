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

use SimpleSAML\Kernel;
use SimpleSAML\Logger;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\ExpiredEntriesCleaner;

/**
 * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
 * @throws \Exception
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

    try {
        $kernel = new Kernel(ModuleConfig::MODULE_NAME);
        $kernel->boot();
        /** @var \SimpleSAML\Module\oidc\Services\ExpiredEntriesCleaner $cleaner */
        $cleaner = $kernel->getContainer()->get(ExpiredEntriesCleaner::class);
        $cleaner->clean();

        $croninfo['summary'][] = 'Module `oidc` clean up. Removed expired entries from storage.';
    } catch (Throwable $e) {
        $message = 'Module `oidc` clean up cron script failed: ' . $e->getMessage();
        Logger::warning($message);
        $croninfo['summary'][] = $message;
    }
}
