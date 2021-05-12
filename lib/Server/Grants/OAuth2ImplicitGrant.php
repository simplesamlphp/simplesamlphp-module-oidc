<?php

namespace SimpleSAML\Modules\OpenIDConnect\Server\Grants;

use League\OAuth2\Server\Grant\ImplicitGrant;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest as OAuth2AuthorizationRequest;
use Psr\Http\Message\ServerRequestInterface;

class OAuth2ImplicitGrant extends ImplicitGrant
{
    /**
     * {@inheritdoc}
     */
    public function validateAuthorizationRequest(ServerRequestInterface $request): OAuth2AuthorizationRequest
    {
        return new OAuth2AuthorizationRequest();
    }
}
