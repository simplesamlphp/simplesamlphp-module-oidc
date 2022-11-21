<?php

namespace SimpleSAML\Module\oidc\Utils\Checker\Rules;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entity\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\ConfigurationService;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Result;
use SimpleSAML\Module\oidc\Utils\ScopeHelper;

class ScopeOfflineAccessRule extends AbstractRule
{
    protected ConfigurationService $configurationService;

    public function __construct(ConfigurationService $configurationService)
    {
        $this->configurationService = $configurationService;
    }

    /**
     * @inheritDoc
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
        /** @var ClientEntityInterface $client */
        $client = $currentResultBag->getOrFail(ClientIdRule::class)->getValue();
        /** @var ScopeEntityInterface[] $validScopes */
        $validScopes = $currentResultBag->getOrFail(ScopeRule::class)->getValue();

        // Refresh token should only be released if the client requests it using the 'offline_access' scope.
        // However, for module backwards compatibility we have enabled the deployer to explicitly state that
        // the refresh token should always be released.
        // @see https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess
        // TODO in v3 remove this config option and do as per spec.
        $alwaysIssueRefreshToken = $this->configurationService
            ->getOpenIDConnectConfiguration()
            ->getBoolean('alwaysIssueRefreshToken', true);
        // If the deployer decided to always issue refresh token, we don't have to check offline_access scope.
        if ($alwaysIssueRefreshToken) {
            return new Result($this->getKey(), true);
        }

        // Check if offline_access scope is used. If not, we don't have to check anything else.
        if (! ScopeHelper::scopeExists($validScopes, 'offline_access')) {
            return new Result($this->getKey(), false);
        }

        // Scope offline_access is used. Check if the client has it registered.
        if (! in_array('offline_access', $client->getScopes())) {
            throw OidcServerException::invalidRequest(
                'scope',
                'offline_access scope is not registered for the client',
                null,
                $redirectUri,
                $state,
                $useFragmentInHttpErrorResponses
            );
        }

        return new Result($this->getKey(), true);
    }
}
