<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Admin;

use SimpleSAML\Error\Exception;
use SimpleSAML\Locale\Translate;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Exceptions\AuthorizationException;
use SimpleSAML\Module\oidc\Services\AuthContextService;

class Authorization
{
    public function __construct(
        protected readonly SspBridge $sspBridge,
        protected readonly AuthContextService $authContextService,
    ) {
    }

    public function isAdmin(): bool
    {
        return $this->sspBridge->utils()->auth()->isAdmin();
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\AuthorizationException
     */
    public function requireAdmin(bool $forceAdminAuthentication = false): void
    {
        if ($forceAdminAuthentication) {
            try {
                $this->sspBridge->utils()->auth()->requireAdmin();
            } catch (Exception $exception) {
                throw new AuthorizationException(
                    Translate::noop('Unable to initiate SimpleSAMLphp admin authentication.'),
                    $exception->getCode(),
                    $exception,
                );
            }
        }

        if (! $this->isAdmin()) {
            throw new AuthorizationException(Translate::noop('SimpleSAMLphp admin access required.'));
        }
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\AuthorizationException
     */
    public function requireAdminOrUserWithPermission(string $permission): void
    {
        if ($this->isAdmin()) {
            return;
        }

        try {
            $this->authContextService->requirePermission($permission);
        } catch (\Exception) {
            // TODO mivanci v7 log this exception
        }

        // If we get here, the user does not have the required permission, or permissions are not enabled.
        // Fallback to admin authentication.
        $this->requireAdmin(true);
    }

    public function getUserId(): string
    {
        return $this->authContextService->getAuthUserId();
    }
}
