<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Services;

use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\AuthCodeRepository;
use SimpleSAML\Module\oidc\Repositories\IssuerStateRepository;
use SimpleSAML\Module\oidc\Repositories\PushedAuthorizationRequestRepository;
use SimpleSAML\Module\oidc\Repositories\RefreshTokenRepository;

/**
 * Removes expired / invalid entries from storage.
 *
 * This is intended to be run from the cron hook (oidc_hook_cron). It is
 * registered as a public service so it can be fetched from the
 * (otherwise private) Symfony DI container after booting the module Kernel.
 */
class ExpiredEntriesCleaner
{
    public function __construct(
        private readonly AccessTokenRepository $accessTokenRepository,
        private readonly AuthCodeRepository $authCodeRepository,
        private readonly RefreshTokenRepository $refreshTokenRepository,
        private readonly IssuerStateRepository $issuerStateRepository,
        private readonly PushedAuthorizationRequestRepository $pushedAuthorizationRequestRepository,
    ) {
    }

    public function clean(): void
    {
        $this->accessTokenRepository->removeExpired();
        $this->authCodeRepository->removeExpired();
        $this->refreshTokenRepository->removeExpired();
        $this->issuerStateRepository->removeInvalid();
        $this->pushedAuthorizationRequestRepository->removeExpired();
    }
}
