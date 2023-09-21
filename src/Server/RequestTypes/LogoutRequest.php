<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestTypes;

use Lcobucci\JWT\UnencryptedToken;

class LogoutRequest
{
    public function __construct(
        /**
         * ID Token previously issued by the OP to the RP passed to the Logout Endpoint as a hint about the End-User's
         * current authenticated session with the Client. This is used as an indication of the identity of the
         * End-User that the RP is requesting be logged out by the OP.
         */
        protected ?UnencryptedToken $idTokenHint = null,
        /**
         * URL to which the RP is requesting that the End-User's User Agent be redirected after a logout has been
         * performed. The value MUST have been previously registered with the OP.An id_token_hint is also
         * REQUIRED when this parameter is included.
         */
        protected ?string $postLogoutRedirectUri = null,
        /**
         * Opaque value used by the RP to maintain state between the logout request and the callback to the endpoint
         * specified by the post_logout_redirect_uri parameter. If included in the logout request, the OP passes
         * this value back to the RP using the state parameter when redirecting the User Agent back to the RP.
         */
        protected ?string $state = null,
        /**
         * End-User's preferred languages and scripts for the user interface, represented as a space-separated list of
         * BCP47 [RFC5646] language tag values, ordered by preference.
         */
        protected ?string $uiLocales = null
    ) {
    }

    public function getIdTokenHint(): ?UnencryptedToken
    {
        return $this->idTokenHint;
    }

    public function setIdTokenHint(?UnencryptedToken $idTokenHint): LogoutRequest
    {
        $this->idTokenHint = $idTokenHint;
        return $this;
    }

    public function getPostLogoutRedirectUri(): ?string
    {
        return $this->postLogoutRedirectUri;
    }

    public function setPostLogoutRedirectUri(?string $postLogoutRedirectUri): LogoutRequest
    {
        $this->postLogoutRedirectUri = $postLogoutRedirectUri;
        return $this;
    }

    public function getState(): ?string
    {
        return $this->state;
    }

    public function setState(?string $state): LogoutRequest
    {
        $this->state = $state;
        return $this;
    }

    public function getUiLocales(): ?string
    {
        return $this->uiLocales;
    }

    public function setUiLocales(?string $uiLocales): LogoutRequest
    {
        $this->uiLocales = $uiLocales;
        return $this;
    }
}
