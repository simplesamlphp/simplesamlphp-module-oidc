<?php

namespace SimpleSAML\Modules\OpenIDConnect\Server;

use League\OAuth2\Server\AuthorizationServer as OAuth2AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Modules\OpenIDConnect\Server\Exceptions\OidcServerException;

class AuthorizationServer extends OAuth2AuthorizationServer
{
    /**
     * Validate an authorization request
     *
     * @param ServerRequestInterface $request
     *
     * @throws OAuthServerException
     *
     * @return AuthorizationRequest
     */
    public function validateAuthorizationRequest(ServerRequestInterface $request): AuthorizationRequest
    {
        // TODO mivanci
        // Check client_id
        // Check redirect_uri
        // Get state
        // Check if response_type is enabled

        foreach ($this->enabledGrantTypes as $grantType) {
            if ($grantType->canRespondToAuthorizationRequest($request)) {
                return $grantType->validateAuthorizationRequest($request);
            }
        }

        throw OidcServerException::unsupportedResponseType();
    }
}
