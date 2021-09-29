<?php

namespace SimpleSAML\Module\oidc\Utils\Checker\Rules;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Result;
use Throwable;

class ScopeRule extends AbstractRule
{
    protected ScopeRepositoryInterface $scopeRepository;

    public function __construct(ScopeRepositoryInterface $scopeRepository)
    {
        $this->scopeRepository = $scopeRepository;
    }

    /**
     * @inheritDoc
     * @throws Throwable
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        bool $useFragmentInHttpErrorResponses = false,
        array $allowedServerRequestMethods = ['GET']
    ): ?ResultInterface {
        /** @var string $redirectUri */
        $redirectUri = $currentResultBag->getOrFail(RedirectUriRule::class)->getValue();
        /** @var string|null $state */
        $state = $currentResultBag->getOrFail(StateRule::class)->getValue();
        /** @var string $defaultScope */
        $defaultScope = $data['default_scope'] ?? '';
        /** @var string $scopeDelimiterString */
        $scopeDelimiterString = $data['scope_delimiter_string'] ?? ' ';

        $scopes = $this->convertScopesQueryStringToArray(
            $request->getQueryParams()['scope'] ?? $defaultScope,
            $scopeDelimiterString
        );

        $validScopes = [];

        foreach ($scopes as $scopeItem) {
            $scope = $this->scopeRepository->getScopeEntityByIdentifier($scopeItem);

            if ($scope instanceof ScopeEntityInterface === false) {
                throw OidcServerException::invalidScope($scopeItem, $redirectUri, $state);
            }

            $validScopes[] = $scope;
        }

        return new Result($this->getKey(), $validScopes);
    }

    /**
     * Converts a scopes query string to an array to easily iterate for validation.
     *
     * @param string $scopes
     * @param string $scopeDelimiterString
     * @return array
     */
    protected function convertScopesQueryStringToArray(string $scopes, string $scopeDelimiterString): array
    {
        return array_filter(explode($scopeDelimiterString, trim($scopes)), function ($scope) {
            return !empty($scope);
        });
    }
}
