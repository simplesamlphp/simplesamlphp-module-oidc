<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\ValueAbstracts;

use SimpleSAML\OpenID\Codebooks\ResponseModesEnum;

/**
 * Where an error response to an authorization request goes: the client's redirect URI, with the request's `state`
 * (RFC 6749 sections 4.1.2.1 and 4.2.2.1), in the request's response mode. It is kept in the authentication state
 * while the End-User authenticates, so that an authentication the End-User cancels is answered to the client
 * (AuthenticationService::rethrowAuthenticationException()). SimpleSAMLphp keeps that state in the session,
 * serialized, so the response mode is kept by its value: the `form_post` one holds the services which render its
 * page. A request made with a Pushed Authorization Request carries its `request_uri`, which the error response
 * consumes, as a successful one does (AuthorizationServer::completeAuthorizationRequest()).
 */
class AuthorizationErrorRedirect
{
    public function __construct(
        protected readonly string $redirectUri,
        protected readonly ?string $state = null,
        protected readonly ?ResponseModesEnum $responseMode = null,
        protected readonly ?string $pushedAuthorizationRequestUri = null,
    ) {
    }


    public function getRedirectUri(): string
    {
        return $this->redirectUri;
    }


    public function getState(): ?string
    {
        return $this->state;
    }


    public function getResponseMode(): ?ResponseModesEnum
    {
        return $this->responseMode;
    }


    public function getPushedAuthorizationRequestUri(): ?string
    {
        return $this->pushedAuthorizationRequestUri;
    }
}
