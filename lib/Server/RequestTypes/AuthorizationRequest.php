<?php

namespace SimpleSAML\Modules\OpenIDConnect\Server\RequestTypes;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest as OAuth2AuthorizationRequest;
use SimpleSAML\Modules\OpenIDConnect\Server\Exceptions\OidcServerException;
use SimpleSAML\Modules\OpenIDConnect\Utils\Arr;

class AuthorizationRequest extends OAuth2AuthorizationRequest
{
    /**
     * @var string|null
     */
    protected $nonce;

    /**
     * @return string|null
     */
    public function getNonce(): ?string
    {
        return $this->nonce;
    }

    /**
     * @param string $nonce
     */
    public function setNonce(string $nonce): void
    {
        $this->nonce = $nonce;
    }

    /**
     * @param OAuth2AuthorizationRequest $oAuth2authorizationRequest
     *
     * @return AuthorizationRequest
     * @throws OidcServerException
     */
    public static function fromOAuth2AuthorizationRequest(
        OAuth2AuthorizationRequest $oAuth2authorizationRequest
    ): AuthorizationRequest {
        static::validateOptionalOAuth2ButRequiredOidcParams($oAuth2authorizationRequest);

        $authorizationRequest = new self();
        $authorizationRequest->setGrantTypeId($oAuth2authorizationRequest->getGrantTypeId());

        $authorizationRequest->setClient($oAuth2authorizationRequest->getClient());
        $authorizationRequest->setRedirectUri($oAuth2authorizationRequest->getRedirectUri());
        $authorizationRequest->setScopes($oAuth2authorizationRequest->getScopes());
        $authorizationRequest->setCodeChallenge($oAuth2authorizationRequest->getCodeChallenge());
        $authorizationRequest->setCodeChallengeMethod($oAuth2authorizationRequest->getCodeChallengeMethod());

        $state = $oAuth2authorizationRequest->getState();
        if (null !== $state) {
            $authorizationRequest->setState($state);
        }

        return $authorizationRequest;
    }

    /**
     * Check if the given authorization request is OIDC authorization request candidate.
     *
     * @param OAuth2AuthorizationRequest $authorizationRequest
     * @return bool
     */
    public static function isOidcCandidate(OAuth2AuthorizationRequest $authorizationRequest): bool
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
     * @param OAuth2AuthorizationRequest $authorizationRequest OAuth2 validated authorization request.
     * @throws OidcServerException
     */
    public static function validateOptionalOAuth2ButRequiredOidcParams(
        OAuth2AuthorizationRequest $authorizationRequest
    ): void {
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
