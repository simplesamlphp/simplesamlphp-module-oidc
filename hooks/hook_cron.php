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
use SimpleSAML\Module\oidc\StatusList\StatusListLifecycle;
use SimpleSAML\Module\oidc\StatusList\StatusListReconciler;

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

    // Kept apart from the clean-up above rather than folded into the same try. The two are unrelated,
    // and a failure of one says nothing about whether the other should run.
    try {
        $kernel = new Kernel(ModuleConfig::MODULE_NAME);
        $kernel->boot();
        /** @var \SimpleSAML\Module\oidc\StatusList\StatusListReconciler $reconciler */
        $reconciler = $kernel->getContainer()->get(StatusListReconciler::class);
        $invalidated = $reconciler->reconcile();

        if ($invalidated > 0) {
            $croninfo['summary'][] = sprintf(
                'Module `oidc` Status List reconciliation. Invalidated %d published token(s) which no ' .
                'longer described their list.',
                $invalidated,
            );
        }
    } catch (Throwable $e) {
        $message = 'Module `oidc` Status List reconciliation cron script failed: ' . $e->getMessage();
        Logger::warning($message);
        $croninfo['summary'][] = $message;
    }

    // Again on its own, for the same reason. This one is also the only place which notices that a
    // credential has expired, which is a privacy undertaking rather than housekeeping, so it must not be
    // skipped because something before it went wrong.
    // Gathered here and appended in one go below, since this step has more than one thing to say.
    $lifecycleSummary = [];

    try {
        $kernel = new Kernel(ModuleConfig::MODULE_NAME);
        $kernel->boot();
        /** @var \SimpleSAML\Module\oidc\StatusList\StatusListLifecycle $lifecycle */
        $lifecycle = $kernel->getContainer()->get(StatusListLifecycle::class);
        $report = $lifecycle->run();

        if ($report->hasChanges()) {
            $lifecycleSummary[] = sprintf(
                'Module `oidc` Status List lifecycle. Forgot which credential held which index for %d ' .
                'expired credential(s), deactivated %d superseded list(s), retired %d list(s), removed ' .
                '%d entry row(s) belonging to retired list(s), pruned %d audit row(s).',
                $report->getClearedLinkages(),
                $report->getDeactivatedStatusLists(),
                $report->getRetiredStatusLists(),
                $report->getPurgedEntries(),
                $report->getPrunedAuditRows(),
            );
        }

        // Reported as well as logged. A step which keeps failing is invisible in a log nobody reads,
        // and one of them stops personal data being deleted on time.
        foreach ($report->getFailures() as $failure) {
            $lifecycleSummary[] = 'Module `oidc` Status List lifecycle. ' . $failure;
        }
    } catch (Throwable $e) {
        $message = 'Module `oidc` Status List lifecycle cron script failed: ' . $e->getMessage();
        Logger::warning($message);
        $lifecycleSummary[] = $message;
    }

    $croninfo['summary'] = array_merge($croninfo['summary'], $lifecycleSummary);
}
