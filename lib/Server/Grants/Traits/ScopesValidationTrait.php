<?php

namespace SimpleSAML\Modules\OpenIDConnect\Server\Grants\Traits;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Modules\OpenIDConnect\Server\Exceptions\OidcServerException;

trait ScopesValidationTrait
{
    /**
     * @param ServerRequestInterface $request
     * @param ScopeRepositoryInterface $scopeRepository
     * @param string $defaultScope
     * @param string|null $redirectUri
     * @param string|null $state
     * @return array
     * @throws OidcServerException
     */
    protected function getScopesOrFail(
        ServerRequestInterface $request,
        ScopeRepositoryInterface $scopeRepository,
        string $defaultScope = '',
        string $redirectUri = null,
        string $state = null
    ): array {
        $scopes = $this->convertScopesQueryStringToArray($request->getQueryParams()['scope'] ?? $defaultScope);

        $validScopes = [];

        foreach ($scopes as $scopeItem) {
            $scope = $scopeRepository->getScopeEntityByIdentifier($scopeItem);

            if ($scope instanceof ScopeEntityInterface === false) {
                throw OidcServerException::invalidScope($scopeItem, $redirectUri, $state);
            }

            $validScopes[] = $scope;
        }

        return $validScopes;
    }

    /**
     * Converts a scopes query string to an array to easily iterate for validation.
     *
     * @param string $scopes
     *
     * @return array
     */
    protected function convertScopesQueryStringToArray(string $scopes): array
    {
        return \array_filter(\explode(self::SCOPE_DELIMITER_STRING, \trim($scopes)), function ($scope) {
            return !empty($scope);
        });
    }
}
