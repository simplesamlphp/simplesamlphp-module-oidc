<?php

namespace SimpleSAML\Module\oidc\Utils\Checker\Rules;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Result;

class RequiredOpenIdScopeRule extends AbstractRule
{
    /**
     * @inheritDoc
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        array $data = [],
        bool $useFragmentInHttpErrorResponses = false,
        array $allowedServerRequestMethods = ['GET']
    ): ?ResultInterface {
        /** @var string $redirectUri */
        $redirectUri = $currentResultBag->getOrFail(RedirectUriRule::class)->getValue();
        /** @var string|null $state */
        $state = $currentResultBag->getOrFail(StateRule::class)->getValue();
        /** @var ScopeEntityInterface[] $validScopes */
        $validScopes = $currentResultBag->getOrFail(ScopeRule::class)->getValue();

        $isOpenIdScopePresent = (bool) array_filter($validScopes, function ($scopeEntity) {
            return $scopeEntity->getIdentifier() === 'openid';
        });

        if (! $isOpenIdScopePresent) {
            throw OidcServerException::invalidRequest(
                'scope',
                'Scope openid is required',
                null,
                $redirectUri,
                $state,
                $useFragmentInHttpErrorResponses
            );
        }

        return new Result($this->getKey(), $isOpenIdScopePresent);
    }
}
