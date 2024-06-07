<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories;

use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\CodeChallengeVerifiersRepository;
use SimpleSAML\Module\oidc\Repositories\ScopeRepository;
use SimpleSAML\Module\oidc\Services\AuthenticationService;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Checker\RequestRulesManager;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\AcrValuesRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\AddClaimsToIdTokenRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\ClientIdRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\CodeChallengeMethodRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\CodeChallengeRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\IdTokenHintRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\MaxAgeRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\PostLogoutRedirectUriRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\PromptRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\RedirectUriRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\RequestedClaimsRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\RequestParameterRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\RequiredNonceRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\RequiredOpenIdScopeRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\ResponseTypeRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\ScopeOfflineAccessRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\ScopeRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\StateRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\UiLocalesRule;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;

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
    ) {
    }

    /**
     * @param \SimpleSAML\Module\oidc\Utils\Checker\Interfaces\RequestRuleInterface[]|null $rules
     * @return \SimpleSAML\Module\oidc\Utils\Checker\RequestRulesManager
     */
    public function build(?array $rules = null): RequestRulesManager
    {
        $rules = $rules ?? $this->getDefaultRules();
        return new RequestRulesManager($rules, $this->logger);
    }

    /**
     * @return \SimpleSAML\Module\oidc\Utils\Checker\Interfaces\RequestRuleInterface[]
     */
    private function getDefaultRules(): array
    {
        return [
            new StateRule(),
            new ClientIdRule($this->clientRepository),
            new RedirectUriRule(),
            new RequestParameterRule(),
            new PromptRule($this->authSimpleFactory, $this->authenticationService),
            new MaxAgeRule($this->authSimpleFactory, $this->authenticationService),
            new ScopeRule($this->scopeRepository),
            new RequiredOpenIdScopeRule(),
            new CodeChallengeRule(),
            new CodeChallengeMethodRule($this->codeChallengeVerifiersRepository),
            new RequestedClaimsRule($this->claimTranslatorExtractor),
            new AddClaimsToIdTokenRule(),
            new RequiredNonceRule(),
            new ResponseTypeRule(),
            new IdTokenHintRule($this->moduleConfig, $this->cryptKeyFactory),
            new PostLogoutRedirectUriRule($this->clientRepository),
            new UiLocalesRule(),
            new AcrValuesRule(),
            new ScopeOfflineAccessRule(),
        ];
    }
}
