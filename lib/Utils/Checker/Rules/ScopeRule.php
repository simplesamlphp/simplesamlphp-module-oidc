<?php

namespace SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Modules\OpenIDConnect\Server\Exceptions\OidcServerException;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\RequestRuleInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Result;

class ScopeRule implements RequestRuleInterface
{
    /**
     * @var ScopeRepositoryInterface $scopeRepository
     */
    protected $scopeRepository;

    public function __construct(ScopeRepositoryInterface $scopeRepository)
    {
        $this->scopeRepository = $scopeRepository;
    }

    /**
     * @inheritDoc
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        array $data
    ): ?ResultInterface {
        /** @var string $redirectUri */
        $redirectUri = $currentResultBag->getOrFail('redirect_uri')->getValue();
        /** @var string|null $state */
        $state = $currentResultBag->getOrFail('state')->getValue();
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

        return new Result('scope', $validScopes);
    }

    /**
     * Converts a scopes query string to an array to easily iterate for validation.
     *
     * @param string $scopes
     *
     * @return array
     */
    protected function convertScopesQueryStringToArray(string $scopes, string $scopeDelimiterString): array
    {
        return \array_filter(\explode($scopeDelimiterString, \trim($scopes)), function ($scope) {
            return !empty($scope);
        });
    }
}
