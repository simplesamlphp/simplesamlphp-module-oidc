<?php

namespace SimpleSAML\Module\oidc\Utils\Checker\Rules;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use LogicException;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entity\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Result;

class ScopeOfflineAccessRule extends AbstractRule
{
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

        // Check if offline_access scope is used. If not, we don't have to check anything else.
        if (! $this->isOfflineAccessScopeUsed($validScopes)) {
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

    /**
     * @param ScopeEntityInterface[] $scopes
     * @return bool
     */
    protected function isOfflineAccessScopeUsed(array $scopes): bool
    {
        foreach ($scopes as $scope) {
            if ($scope->getIdentifier() === 'offline_access') {
                return true;
            }
        }

        return false;
    }
}
