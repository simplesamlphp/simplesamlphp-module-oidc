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
use SimpleSAML\Module\oidc\Utils\ParamsResolver;

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
        private readonly ParamsResolver $paramsResolver,
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
            new StateRule($this->paramsResolver),
            new ClientIdRule($this->paramsResolver, $this->clientRepository),
            new RedirectUriRule($this->paramsResolver),
            new RequestParameterRule($this->paramsResolver),
            new PromptRule($this->paramsResolver, $this->authSimpleFactory, $this->authenticationService),
            new MaxAgeRule($this->paramsResolver, $this->authSimpleFactory, $this->authenticationService),
            new ScopeRule($this->paramsResolver, $this->scopeRepository),
            new RequiredOpenIdScopeRule($this->paramsResolver),
            new CodeChallengeRule($this->paramsResolver),
            new CodeChallengeMethodRule($this->paramsResolver, $this->codeChallengeVerifiersRepository),
            new RequestedClaimsRule($this->paramsResolver, $this->claimTranslatorExtractor),
            new AddClaimsToIdTokenRule($this->paramsResolver),
            new RequiredNonceRule($this->paramsResolver),
            new ResponseTypeRule($this->paramsResolver),
            new IdTokenHintRule($this->paramsResolver, $this->moduleConfig, $this->cryptKeyFactory),
            new PostLogoutRedirectUriRule($this->paramsResolver, $this->clientRepository),
            new UiLocalesRule($this->paramsResolver),
            new AcrValuesRule($this->paramsResolver),
            new ScopeOfflineAccessRule($this->paramsResolver),
        ];
    }
}
