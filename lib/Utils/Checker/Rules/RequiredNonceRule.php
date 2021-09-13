<?php

namespace SimpleSAML\Module\oidc\Utils\Checker\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Result;

class RequiredNonceRule extends AbstractRule
{
    /**
     * @inheritDoc
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        array $data = [],
        bool $useFragmentInHttpErrorResponses = false
    ): ?ResultInterface {
        /** @var string $redirectUri */
        $redirectUri = $currentResultBag->getOrFail(RedirectUriRule::class)->getValue();
        /** @var string|null $state */
        $state = $currentResultBag->getOrFail(StateRule::class)->getValue();

        /** @var string|null $nonce */
        $nonce = $request->getQueryParams()['nonce'] ?? null;

        if ($nonce === null || $nonce === '') {
            throw OidcServerException::invalidRequest(
                'nonce',
                'nonce is required',
                null,
                $redirectUri,
                $state,
                $useFragmentInHttpErrorResponses
            );
        }

        return new Result($this->getKey(), $nonce);
    }
}
