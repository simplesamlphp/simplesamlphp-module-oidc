<?php

namespace SimpleSAML\Modules\OpenIDConnect\Server\Grants\Interfaces;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Modules\OpenIDConnect\Entity\Interfaces\ClientEntityInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest as OAuth2AuthorizationRequest;

interface AuthorizationValidatableWithClientAndRedirectUriInterface
{
    /**
     * Validate authorization request using already validated client and redirect_uri. This is to evade usage of
     * original validateAuthorizationRequest() method in which it is expected to validate client and redirect_uri.
     *
     * @param ServerRequestInterface $request
     * @param ClientEntityInterface $client
     * @param string $redirectUri
     * @param string|null $state
     * @return OAuth2AuthorizationRequest
     */
    public function validateAuthorizationRequestWithClientAndRedirectUri(
        ServerRequestInterface $request,
        ClientEntityInterface $client,
        string $redirectUri,
        string $state = null
    ): OAuth2AuthorizationRequest;
}
