<?php

namespace SimpleSAML\Module\oidc\Utils\Checker\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Result;

class PostLogoutRedirectUriRule extends AbstractRule
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
        $idTokenHint = $currentResultBag->getOrFail(IdTokenHintRule::class)->getValue();

        $postLogoutRedirectUri = $this->getParamFromRequestBasedOnAllowedMethods(
            'post_logout_redirect_uri',
            $request,
            $allowedServerRequestMethods
        );

        if ($postLogoutRedirectUri !== null && $idTokenHint === null) {
            $hint = 'id_token_hint is mandatory when post_logout_redirect_uri is included';
            throw OidcServerException::invalidRequest('id_token_hint', $hint);
        }

        // TODO validate if post_logout_redirect_uri is registered on client

        return new Result($this->getKey(), $postLogoutRedirectUri);
    }
}
