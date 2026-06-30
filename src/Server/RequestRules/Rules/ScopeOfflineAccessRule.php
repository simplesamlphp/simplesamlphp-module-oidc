<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;

/**
 * @extends AbstractRule<bool>
 */
class ScopeOfflineAccessRule extends AbstractRule
{
    /**
     * @inheritDoc
     *
     * @throws \Throwable
     *
     * @param ResponseModeInterface $responseMode
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        ResponseModeInterface $responseMode = new QueryResponseMode(),
        array $allowedServerRequestMethods = [HttpMethodsEnum::GET],
    ): ?Result {
        $loggerService->debug('ScopeOfflineAccessRule::checkRule');

        $redirectUri = $currentResultBag->getOrFail(ClientRedirectUriRule::class)->getValue();
        $state = $currentResultBag->getOrFail(StateRule::class)->getValue();
        $client = $currentResultBag->getOrFail(ClientRule::class)->getValue();
        $validScopes = $currentResultBag->getOrFail(ScopeRule::class)->getValue();

        // Check if offline_access scope is used. If not, we don't have to check anything else.
        if (! $this->helpers->scope()->exists($validScopes, 'offline_access')) {
            return new Result($this->getKey(), false);
        }

        // Scope offline_access is used. Check if the client has it registered.
        if (! in_array('offline_access', $client->getScopes(), true)) {
            $loggerService->notice(
                'Authorization request rejected: `offline_access` scope requested but not registered for the client.',
                ['client_id' => $client->getIdentifier()],
            );
            throw OidcServerException::invalidRequest(
                'scope',
                'offline_access scope is not registered for the client',
                null,
                $redirectUri,
                $state,
                $responseMode,
            );
        }

        return new Result($this->getKey(), true);
    }
}
