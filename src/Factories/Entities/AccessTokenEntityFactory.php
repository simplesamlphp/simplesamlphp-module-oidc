<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories\Entities;

use DateTimeImmutable;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\ClientEntityInterface as OAuth2ClientEntityInterface;
use SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\JsonWebTokenBuilderService;

class AccessTokenEntityFactory
{
    public function __construct(
        protected readonly Helpers $helpers,
        protected readonly CryptKey $privateKey,
        protected readonly JsonWebTokenBuilderService $jsonWebTokenBuilderService,
        protected readonly ScopeEntityFactory $scopeEntityFactory,
    ) {
    }

    /**
     * @param \League\OAuth2\Server\Entities\ScopeEntityInterface[] $scopes
     */
    public function fromData(
        string $id,
        OAuth2ClientEntityInterface $clientEntity,
        array $scopes,
        DateTimeImmutable $expiryDateTime,
        int|string|null $userIdentifier = null,
        ?string $authCodeId = null,
        ?array $requestedClaims = null,
        ?bool $isRevoked = false,
        ?FlowTypeEnum $flowTypeEnum = null,
        ?array $authorizationDetails = null,
        ?string $boundClientId = null,
        ?string $boundRedirectUri = null,
    ): AccessTokenEntity {
        return new AccessTokenEntity(
            $id,
            $clientEntity,
            $scopes,
            $expiryDateTime,
            $this->privateKey,
            $this->jsonWebTokenBuilderService,
            $userIdentifier,
            $authCodeId,
            $requestedClaims,
            $isRevoked,
            flowTypeEnum: $flowTypeEnum,
            authorizationDetails: $authorizationDetails,
            boundClientId: $boundClientId,
            boundRedirectUri: $boundRedirectUri,
        );
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function fromState(array $state): AccessTokenEntity
    {
        if (
            !is_string($state['scopes']) ||
            !is_string($state['id']) ||
            !is_string($state['expires_at']) ||
            !is_a($state['client'], ClientEntityInterface::class)
        ) {
            throw OidcServerException::serverError('Invalid Access Token Entity state');
        }

        $stateScopes = json_decode($state['scopes'], true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($stateScopes)) {
            throw OidcServerException::serverError('Invalid Access Token Entity state: scopes');
        }

        /** @psalm-var string $scope */
        $scopes = array_map(fn(string $scope) => $this->scopeEntityFactory->fromData($scope), $stateScopes);

        $id = $state['id'];
        $expiryDateTime = $this->helpers->dateTime()->getUtc($state['expires_at']);
        $userIdentifier = empty($state['user_id']) ? null : (string)$state['user_id'];
        $client = $state['client'];
        $isRevoked = (bool) $state['is_revoked'];
        $authCodeId = empty($state['auth_code_id']) ? null : (string)$state['auth_code_id'];

        $stateRequestedClaims = json_decode(
            empty($state['requested_claims']) ? '[]' : (string)$state['requested_claims'],
            true,
            512,
            JSON_THROW_ON_ERROR,
        );
        if (!is_array($stateRequestedClaims)) {
            throw OidcServerException::serverError('Invalid Access Token Entity state: requested claims');
        }

        $flowType = empty($state['flow_type']) ? null : FlowTypeEnum::tryFrom((string)$state['flow_type']);
        /** @psalm-suppress MixedAssignment */
        $authorizationDetails = isset($state['authorization_details']) && is_string($state['authorization_details']) ?
        json_decode($state['authorization_details'], true, 512, JSON_THROW_ON_ERROR) :
        null;
        $authorizationDetails = is_array($authorizationDetails) ? $authorizationDetails : null;

        $boundClientId = empty($state['bound_client_id']) ? null : (string)$state['bound_client_id'];
        $boundRedirectUri = empty($state['bound_redirect_uri']) ? null : (string)$state['bound_redirect_uri'];

        return $this->fromData(
            $id,
            $client,
            $scopes,
            $expiryDateTime,
            $userIdentifier,
            $authCodeId,
            $stateRequestedClaims,
            $isRevoked,
            $flowType,
            $authorizationDetails,
            $boundClientId,
            $boundRedirectUri,
        );
    }
}
