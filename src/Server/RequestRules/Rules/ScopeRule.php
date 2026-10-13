<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;

/**
 * @extends \SimpleSAML\Module\oidc\Server\RequestRules\Rules\AbstractRule<\League\OAuth2\Server\Entities\ScopeEntityInterface[]>
 */
class ScopeRule extends AbstractRule
{
    public function __construct(
        RequestParamsResolver $requestParamsResolver,
        Helpers $helpers,
        protected ScopeRepositoryInterface $scopeRepository,
        protected ModuleConfig $moduleConfig,
    ) {
        parent::__construct($requestParamsResolver, $helpers);
    }


    /**
     * @inheritDoc
     *
     * @throws \Throwable
     *
     * @param \SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface $responseMode
     * @param \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum[] $allowedServerRequestMethods
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        ResponseModeInterface $responseMode = new QueryResponseMode(),
        array $allowedServerRequestMethods = [HttpMethodsEnum::GET],
    ): ?Result {
        $loggerService->debug('ScopeRule::checkRule.');

        /** @var string $defaultScope */
        $defaultScope = $data['default_scope'] ?? '';
        /** @var non-empty-string $scopeDelimiterString */
        $scopeDelimiterString = $data['scope_delimiter_string'] ?? ' ';

        $loggerService->debug('ScopeRule: defaultScope: ' . ($defaultScope ?: 'N/A'));

        $scopeParam = $this->requestParamsResolver->getAsStringBasedOnAllowedMethods(
            ParamsEnum::Scope->value,
            $request,
            $allowedServerRequestMethods,
        ) ?? $defaultScope;

        $loggerService->debug('ScopeRule: scopeParam: ' . $scopeParam);
        $scopes = $this->helpers->str()->convertScopesStringToArray($scopeParam, $scopeDelimiterString);

        // A credential configuration whose metadata states no scope is requested through authorization_details
        // only (OpenID4VCI 1.0 section 12.2.4). Its id is still the scope a grant of it is held under, inside the
        // module (AuthCodeGrant adds it for an authorization detail), but not one a client may ask for.
        $authorizationDetailsOnlyIds = $this->moduleConfig->getVciCredentialConfigurationIdsWithoutScope();

        $validScopes = [];
        $ignoredScopes = [];

        // A scope value this server does not support is ignored rather than refused: OpenID4VCI 1.0 section 5.1.2
        // has a Credential Issuer ignore unknown scope values, OpenID Connect Core 1.0 section 3.1.2.1 has an
        // OpenID Provider ignore those it does not understand, and RFC 6749 section 3.3 lets an authorization
        // server grant less than was asked for. What is left decides the request: an OpenID Connect request
        // without 'openid' is refused by RequiredOpenIdScopeRule, a credential request which names no credential
        // by OfferedCredentialsRule, and the token response states the scopes granted.
        foreach ($scopes as $scopeItem) {
            $scope = $this->scopeRepository->getScopeEntityByIdentifier($scopeItem);

            if (
                $scope instanceof ScopeEntityInterface === false ||
                in_array($scopeItem, $authorizationDetailsOnlyIds, true)
            ) {
                $ignoredScopes[] = $scopeItem;
                continue;
            }
            $loggerService->debug('ScopeRule: Valid scope: ' . $scopeItem);
            $validScopes[] = $scope;
        }

        if ($ignoredScopes !== []) {
            $client = $currentResultBag->get(ClientRule::class)?->getValue();
            $loggerService->notice(
                'Authorization request: scope values this server does not support were ignored.',
                [
                    'client_id' => $client instanceof ClientEntityInterface ? $client->getIdentifier() : null,
                    'ignored_scopes' => $ignoredScopes,
                ],
            );
        }

        return new Result($this->getKey(), $validScopes);
    }
}
