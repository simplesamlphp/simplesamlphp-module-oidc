<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestTypes;

use League\OAuth2\Server\RequestTypes\AuthorizationRequest as OAuth2AuthorizationRequest;
use SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum;

class AuthorizationRequest extends OAuth2AuthorizationRequest
{
    protected ?string $nonce = null;

    protected ?int $authTime = null;

    /**
     * The JSON object sent as `claims` request parameter.
     * @link https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
     */
    protected ?array $claims = null;

    protected bool $addClaimsToIdToken = false;

    protected ?string $responseType = null;

    protected ?bool $isCookieBasedAuthn = null;

    /**
     * ID of the AuthSource used during authn.
     */
    protected ?string $authSourceId = null;

    /**
     * ACR values requested during authorization request.
     */
    protected ?array $requestedAcrValues = null;

    /**
     * ACR used during authn.
     */
    protected ?string $acr = null;

    /**
     * Current Session ID
     */
    protected ?string $sessionId = null;

    /**
     * Indicates if the request is related to Verifiable Credential Issuance (VCI request).
     *
     * @var bool
     */
    protected bool $isVciRequest = false;

    protected ?FlowTypeEnum $flowType = null;

    /**
     * @var mixed[]|null
     */
    protected ?array $authorizationDetails = null;

    /**
     * Verifiable Credential Issuer state.
     *
     * @var string|null
     */
    protected ?string $issuerState = null;

    public static function fromOAuth2AuthorizationRequest(
        OAuth2AuthorizationRequest $oAuth2authorizationRequest,
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
     * @return array|null
     */
    public function getClaims(): ?array
    {
        return $this->claims;
    }

    /**
     * @param array|null $claims
     */
    public function setClaims(?array $claims): void
    {
        $this->claims = $claims;
    }


    /*
     * @return bool
     */
    public function getAddClaimsToIdToken(): bool
    {
        return $this->addClaimsToIdToken;
    }

    public function setAddClaimsToIdToken(bool $addClaimsToIdToken): void
    {
        $this->addClaimsToIdToken = $addClaimsToIdToken;
    }

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

    public function setIsCookieBasedAuthn(?bool $isCookieBasedAuthn): void
    {
        $this->isCookieBasedAuthn = $isCookieBasedAuthn;
    }

    public function getIsCookieBasedAuthn(): ?bool
    {
        return $this->isCookieBasedAuthn;
    }

    public function setAuthSourceId(?string $authSourceId): void
    {
        $this->authSourceId = $authSourceId;
    }

    public function getAuthSourceId(): ?string
    {
        return $this->authSourceId;
    }

    public function getRequestedAcrValues(): ?array
    {
        return $this->requestedAcrValues;
    }

    public function setRequestedAcrValues(?array $requestedAcrValues): void
    {
        $this->requestedAcrValues = $requestedAcrValues;
    }

    public function getAcr(): ?string
    {
        return $this->acr;
    }

    public function setAcr(?string $acr): void
    {
        $this->acr = $acr;
    }

    /**
     * @return string|null
     */
    public function getSessionId(): ?string
    {
        return $this->sessionId;
    }

    /**
     * @param string|null $sessionId
     */
    public function setSessionId(?string $sessionId): void
    {
        $this->sessionId = $sessionId;
    }

    public function isVciRequest(): bool
    {
        return $this->isVciRequest;
    }

    public function setIsVciRequest(bool $isVciRequest): void
    {
        $this->isVciRequest = $isVciRequest;
    }

    public function getIssuerState(): ?string
    {
        return $this->issuerState;
    }

    public function setIssuerState(?string $issuerState): void
    {
        $this->issuerState = $issuerState;
    }

    public function getFlowType(): ?FlowTypeEnum
    {
        return $this->flowType;
    }

    public function setFlowType(?FlowTypeEnum $flowType): void
    {
        $this->flowType = $flowType;
    }

    public function getAuthorizationDetails(): ?array
    {
        return $this->authorizationDetails;
    }

    public function setAuthorizationDetails(?array $authorizationDetails): void
    {
        $this->authorizationDetails = $authorizationDetails;
    }
}
