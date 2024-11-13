<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Admin;

use SimpleSAML\Error\Exception;
use SimpleSAML\Locale\Translate;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Exceptions\AuthorizationException;

class Authorization
{
    public function __construct(
        protected readonly SspBridge $sspBridge,
    ) {
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\AuthorizationException
     */
    public function requireSspAdmin(bool $forceAdminAuthentication = false): void
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

        if (! $this->sspBridge->utils()->auth()->isAdmin()) {
            throw new AuthorizationException(Translate::noop('SimpleSAMLphp admin access required.'));
        }
    }
}
