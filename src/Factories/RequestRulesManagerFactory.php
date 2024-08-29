<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories;

use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\CodeChallengeVerifiersRepository;
use SimpleSAML\Module\oidc\Repositories\ScopeRepository;
use SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\AcrValuesRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\AddClaimsToIdTokenRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientIdRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\CodeChallengeMethodRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\CodeChallengeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\IdTokenHintRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\MaxAgeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\PostLogoutRedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\PromptRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequestedClaimsRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequestParameterRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequiredNonceRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequiredOpenIdScopeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ResponseTypeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ScopeOfflineAccessRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ScopeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\UiLocalesRule;
use SimpleSAML\Module\oidc\Services\AuthenticationService;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;

class RequestRulesManagerFactory
{
    public function __construct(
        private readonly ModuleConfig $moduleConfig,
        private readonly LoggerService $logger,
        private readonly ClientRepository $clientRepository,
        private readonly AuthSimpleFactory $authSimpleFactory,
        private readonly AuthenticationService $authenticationService,
        private readonly ScopeRepository $scopeRepository,
        private readonly CodeChallengeVerifiersRepository $codeChallengeVerifiersRepository,
        private readonly ClaimTranslatorExtractor $claimTranslatorExtractor,
        private readonly CryptKeyFactory $cryptKeyFactory,
        private readonly RequestParamsResolver $requestParamsResolver,
    ) {
    }

    /**
     * @param \SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\RequestRuleInterface[]|null $rules
     * @return \SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager
     */
    public function build(?array $rules = null): RequestRulesManager
    {
        $rules = $rules ?? $this->getDefaultRules();
        return new RequestRulesManager($rules, $this->logger);
    }

    /**
     * @return \SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\RequestRuleInterface[]
     */
    private function getDefaultRules(): array
    {
        return [
            new StateRule($this->requestParamsResolver),
            new ClientIdRule($this->requestParamsResolver, $this->clientRepository),
            new RedirectUriRule($this->requestParamsResolver),
            new RequestParameterRule($this->requestParamsResolver),
            new PromptRule($this->requestParamsResolver, $this->authSimpleFactory, $this->authenticationService),
            new MaxAgeRule($this->requestParamsResolver, $this->authSimpleFactory, $this->authenticationService),
            new ScopeRule($this->requestParamsResolver, $this->scopeRepository),
            new RequiredOpenIdScopeRule($this->requestParamsResolver),
            new CodeChallengeRule($this->requestParamsResolver),
            new CodeChallengeMethodRule($this->requestParamsResolver, $this->codeChallengeVerifiersRepository),
            new RequestedClaimsRule($this->requestParamsResolver, $this->claimTranslatorExtractor),
            new AddClaimsToIdTokenRule($this->requestParamsResolver),
            new RequiredNonceRule($this->requestParamsResolver),
            new ResponseTypeRule($this->requestParamsResolver),
            new IdTokenHintRule($this->requestParamsResolver, $this->moduleConfig, $this->cryptKeyFactory),
            new PostLogoutRedirectUriRule($this->requestParamsResolver, $this->clientRepository),
            new UiLocalesRule($this->requestParamsResolver),
            new AcrValuesRule($this->requestParamsResolver),
            new ScopeOfflineAccessRule($this->requestParamsResolver),
        ];
    }
}
