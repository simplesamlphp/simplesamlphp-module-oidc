<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Admin;

use SimpleSAML\Error\Exception;
use SimpleSAML\Locale\Translate;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Exceptions\AuthorizationException;
use SimpleSAML\Module\oidc\Services\AuthContextService;
use SimpleSAML\Module\oidc\Services\LoggerService;

class Authorization
{
    public function __construct(
        protected readonly SspBridge $sspBridge,
        protected readonly AuthContextService $authContextService,
        protected readonly LoggerService $loggerService,
    ) {
    }

    public function isAdmin(): bool
    {
        $this->loggerService->debug('Authorization::isAdmin');
        return $this->sspBridge->utils()->auth()->isAdmin();
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\AuthorizationException
     */
    public function requireAdmin(bool $forceAdminAuthentication = false): void
    {
        $this->loggerService->debug('Authorization::requireAdmin');
        $this->loggerService->debug(
            'Authorization: Force admin authentication:',
            ['forceAdminAuthentication' => $forceAdminAuthentication],
        );
        if ($forceAdminAuthentication) {
            $this->loggerService->debug('Authorization: Forcing admin authentication.');
            try {
                $this->sspBridge->utils()->auth()->requireAdmin();
            } catch (Exception $exception) {
                $this->loggerService->error(
                    'Authorization: Forcing admin authentication failed: ' . $exception->getMessage(),
                );
                throw new AuthorizationException(
                    Translate::noop('Unable to initiate SimpleSAMLphp admin authentication.'),
                    $exception->getCode(),
                    $exception,
                );
            }
        }

        if (! $this->isAdmin()) {
            $this->loggerService->error('Authorization: User is NOT admin.');
            throw new AuthorizationException(Translate::noop('SimpleSAMLphp admin access required.'));
        } else {
            $this->loggerService->debug('Authorization: User is admin.');
        }
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\AuthorizationException
     */
    public function requireAdminOrUserWithPermission(string $permission): void
    {
        $this->loggerService->debug('Authorization::requireAdminOrUserWithPermission');
        $this->loggerService->debug('Authorization: For permission: ' . $permission);

        if ($this->isAdmin()) {
            $this->loggerService->debug('Authorization: User is admin, returning.');
            return;
        } else {
            $this->loggerService->debug('Authorization: User is not (authenticated as) admin.');
        }

        try {
            $this->loggerService->debug('Authorization: Checking for user permission.');
            $this->authContextService->requirePermission($permission);
            $this->loggerService->debug('Authorization: User has permission, returning.');
            return;
        } catch (\Exception $exception) {
            $this->loggerService->warning(
                'Authorization: User permission check failed: ' . $exception->getMessage(),
            );
        }

        $this->loggerService->debug('Authorization: Falling back to admin authentication.');

        // If we get here, the user does not have the required permission, or permissions are not enabled.
        // Fallback to admin authentication.
        $this->requireAdmin(true);
    }

    public function getUserId(): string
    {
        return $this->authContextService->getAuthUserId();
    }
}
