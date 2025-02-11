<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Helpers;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;

class Scope
{
    /**
     * @param \League\OAuth2\Server\Entities\ScopeEntityInterface[] $scopes
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function exists(array $scopes, string $scopeIdentifier): bool
    {
        foreach ($scopes as $scope) {
            if (! $scope instanceof ScopeEntityInterface) {
                throw OidcServerException::serverError('Invalid scope element provided.');
            }

            if ($scope->getIdentifier() === $scopeIdentifier) {
                return true;
            }
        }

        return false;
    }
}
