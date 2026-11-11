<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories\Entities;

use DateTimeImmutable;
use League\OAuth2\Server\Entities\ClientEntityInterface as OAuth2ClientEntityInterface;
use SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum;
use SimpleSAML\Module\oidc\Entities\AuthCodeEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;

class AuthCodeEntityFactory
{
    public function __construct(
        protected readonly Helpers $helpers,
        protected readonly ScopeEntityFactory $scopeEntityFactory,
    ) {
    }


    /**
     * @param \League\OAuth2\Server\Entities\ScopeEntityInterface[] $scopes
     */
    public function fromData(
        string $id,
        OAuth2ClientEntityInterface $client,
        array $scopes,
        DateTimeImmutable $expiryDateTime,
        ?string $userIdentifier = null,
        ?string $redirectUri = null,
        ?string $nonce = null,
        ?string $issuerState = null,
        bool $isRevoked = false,
        ?FlowTypeEnum $flowTypeEnum = null,
        ?string $txCode = null,
        ?array $authorizationDetails = null,
        ?string $boundClientId = null,
        ?string $boundRedirectUri = null,
        ?string $dpopJkt = null,
        ?array $offerClaims = null,
        ?string $offerId = null,
    ): AuthCodeEntity {
        return new AuthCodeEntity(
            $id,
            $client,
            $scopes,
            $expiryDateTime,
            $userIdentifier,
            $redirectUri,
            $nonce,
            $isRevoked,
            $flowTypeEnum,
            $txCode,
            $authorizationDetails,
            $boundClientId,
            $boundRedirectUri,
            $issuerState,
            $dpopJkt,
            $offerClaims,
            $offerId,
        );
    }


    /**
     * @throws \Exception
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function fromState(array $state): AuthCodeEntity
    {
        if (
            !is_string($state['scopes']) ||
            !is_string($state['id']) ||
            !is_string($state['expires_at']) ||
            !is_a($state['client'], ClientEntityInterface::class)
        ) {
            throw OidcServerException::serverError('Invalid Auth Code Entity state');
        }

        $stateScopes = json_decode($state['scopes'], true, 512, JSON_THROW_ON_ERROR);

        if (!is_array($stateScopes)) {
            throw OidcServerException::serverError('Invalid Auth Code Entity state: scopes');
        }

        $scopes = array_map(
            /**
             * @return \SimpleSAML\Module\oidc\Entities\ScopeEntity
             */
            fn(string $scope) => $this->scopeEntityFactory->fromData($scope),
            $stateScopes,
        );

        $id = $state['id'];
        $client = $state['client'];
        $expiryDateTime = $this->helpers->dateTime()->getUtc($state['expires_at']);
        $userIdentifier = empty($state['user_id']) ? null : (string)$state['user_id'];
        $redirectUri = empty($state['redirect_uri']) ? null : (string)$state['redirect_uri'];
        $nonce = empty($state['nonce']) ? null : (string)$state['nonce'];
        $isRevoked = (bool) $state['is_revoked'];
        $flowType = empty($state['flow_type']) ? null : FlowTypeEnum::tryFrom((string)$state['flow_type']);
        $txCode = empty($state['tx_code']) ? null : (string)$state['tx_code'];
        $issuerState = empty($state['issuer_state']) ? null : (string)$state['issuer_state'];

        /** @psalm-suppress MixedAssignment */
        $authorizationDetails = isset($state['authorization_details']) && is_string($state['authorization_details']) ?
        json_decode($state['authorization_details'], true, 512, JSON_THROW_ON_ERROR) :
        null;
        $authorizationDetails = is_array($authorizationDetails) ? $authorizationDetails : null;

        $boundClientId = empty($state['bound_client_id']) ? null : (string)$state['bound_client_id'];
        $boundRedirectUri = empty($state['bound_redirect_uri']) ? null : (string)$state['bound_redirect_uri'];
        // A state written before codes were bound (a cached one included) has no such entry: bound to nothing.
        $dpopJkt = empty($state['dpop_jkt']) ? null : (string)$state['dpop_jkt'];
        $offerClaims = $this->offerClaimsFromState($state);
        $offerId = empty($state['offer_id']) ? null : (string)$state['offer_id'];

        return $this->fromData(
            $id,
            $client,
            $scopes,
            $expiryDateTime,
            $userIdentifier,
            $redirectUri,
            $nonce,
            $issuerState,
            $isRevoked,
            $flowType,
            $txCode,
            $authorizationDetails,
            $boundClientId,
            $boundRedirectUri,
            $dpopJkt,
            $offerClaims,
            $offerId,
        );
    }


    /**
     * The attributes a pre-authorized Credential Offer was made with, or null for a code which carries none: one of
     * another flow, or a state written before codes carried them (a cached one included), which has no such entry.
     * An empty JSON array stays an empty array, an offer made with no attributes.
     *
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    protected function offerClaimsFromState(array $state): ?array
    {
        if (!isset($state['offer_claims'])) {
            return null;
        }

        /** @psalm-suppress MixedAssignment */
        $offerClaims = is_string($state['offer_claims']) ?
        json_decode($state['offer_claims'], true, 512, JSON_THROW_ON_ERROR) :
        null;

        if (!is_array($offerClaims)) {
            throw OidcServerException::serverError('Invalid Auth Code Entity state: offer claims');
        }

        return $offerClaims;
    }
}
