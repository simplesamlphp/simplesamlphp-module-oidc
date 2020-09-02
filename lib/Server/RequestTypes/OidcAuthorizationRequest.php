<?php

namespace SimpleSAML\Modules\OpenIDConnect\Server\RequestTypes;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use SimpleSAML\Modules\OpenIDConnect\Server\Exceptions\OidcServerException;
use SimpleSAML\Modules\OpenIDConnect\Utils\Arr;

class OidcAuthorizationRequest extends AuthorizationRequest
{
    /**
     * @var string|null
     */
    protected $nonce;

    /**
     * @return string|null
     */
    public function getNonce()
    {
        return $this->nonce;
    }

    /**
     * @param string $nonce
     */
    public function setNonce(string $nonce)
    {
        $this->nonce = $nonce;
    }

    /**
     * @param AuthorizationRequest $authorizationRequest
     *
     * @return OidcAuthorizationRequest
     * @throws OidcServerException
     */
    public static function fromOAuth2AuthorizationRequest(AuthorizationRequest $authorizationRequest)
    {
        static::validateOptionalOAuth2ButRequiredOidcParams($authorizationRequest);

        $oidcAuthorizationRequest = new self();
        $oidcAuthorizationRequest->setGrantTypeId($authorizationRequest->getGrantTypeId());

        $oidcAuthorizationRequest->setClient($authorizationRequest->getClient());
        $oidcAuthorizationRequest->setRedirectUri($authorizationRequest->getRedirectUri());
        $oidcAuthorizationRequest->setScopes($authorizationRequest->getScopes());
        $oidcAuthorizationRequest->setCodeChallenge($authorizationRequest->getCodeChallenge());
        $oidcAuthorizationRequest->setCodeChallengeMethod($authorizationRequest->getCodeChallengeMethod());

        $state = $authorizationRequest->getState();
        if (null !== $state) {
            $oidcAuthorizationRequest->setState($state);
        }

        return $oidcAuthorizationRequest;
    }

    /**
     * Check if the given authorization request is OIDC authorization request candidate.
     *
     * @param AuthorizationRequest $authorizationRequest
     * @return bool
     */
    public static function isOidcCandidate(AuthorizationRequest $authorizationRequest)
    {
        // Check if the scopes contain 'oidc' scope
        return (bool) Arr::find($authorizationRequest->getScopes(), function (ScopeEntityInterface $scope) {
            return $scope->getIdentifier() === 'openid';
        });
    }

    /**
     * Validate parameters which are not required in OAuth2, but are required in OIDC.
     * The $authorizationRequest should already be OAuth2 validated.
     *
     * @param AuthorizationRequest $authorizationRequest OAuth2 validated authorization request.
     * @throws OidcServerException
     */
    public static function validateOptionalOAuth2ButRequiredOidcParams(AuthorizationRequest $authorizationRequest)
    {
        if (! self::isOidcCandidate($authorizationRequest)) {
            throw OidcServerException::invalidRequest(
                'scope',
                'Scope must contain value openid.'
            );
        }

        if (! $authorizationRequest->getRedirectUri()) {
            throw OidcServerException::invalidRequest(
                'redirect_uri',
                'Redirect URI is required.'
            );
        }
    }
}
