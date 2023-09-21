<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;

class ScopeHelper
{
    /**
     * @param ScopeEntityInterface[] $scopes
     * @return bool
     * @throws OidcServerException
     */
    public static function scopeExists(array $scopes, string $scopeIdentifier): bool
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
