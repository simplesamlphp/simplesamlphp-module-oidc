<?php

namespace SimpleSAML\Module\oidc\Server\RequestTypes;

use League\OAuth2\Server\RequestTypes\AuthorizationRequest as OAuth2AuthorizationRequest;

class AuthorizationRequest extends OAuth2AuthorizationRequest
{
    /**
     * @var string|null
     */
    protected $nonce;

    /**
     * @var int|null
     */
    protected $authTime;

    /**
     * @var bool
     */
    protected $addClaimsToIdToken = false;

    /**
     * @var string|null
     */
    protected $responseType;

    public static function fromOAuth2AuthorizationRequest(
        OAuth2AuthorizationRequest $oAuth2authorizationRequest
    ): AuthorizationRequest {
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
     * @return int|null
     */
    public function getAuthTime(): ?int
    {
        return $this->authTime;
    }

    /**
     * @param int|null $authTime
     */
    public function setAuthTime(?int $authTime): void
    {
        $this->authTime = $authTime;
    }

    /**
     * @return bool
     */
    public function getAddClaimsToIdToken(): bool
    {
        return $this->addClaimsToIdToken;
    }

    /**
     * @param bool $addClaimsToIdToken
     */
    public function setAddClaimsToIdToken(bool $addClaimsToIdToken): void
    {
        $this->addClaimsToIdToken = $addClaimsToIdToken;
    }

    /**
     * @param string $responseType
     */
    public function setResponseType(string $responseType): void
    {
        $this->responseType = $responseType;
    }

    /**
     * @return string|null
     */
    public function getResponseType(): ?string
    {
        return $this->responseType;
    }

    /**
     * Check if access token should be issued in authorization response (implicit flow, hybrid flow...).
     * @return bool
     */
    public function shouldReturnAccessTokenInAuthorizationResponse(): bool
    {
        if ($this->responseType !== null) {
            return in_array('token', explode(' ', $this->responseType), true);
        }

        return false;
    }
}
