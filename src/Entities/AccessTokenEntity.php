<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Entities;

use DateTimeImmutable;
use InvalidArgumentException;
use League\OAuth2\Server\Entities\ClientEntityInterface as OAuth2ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\AccessTokenTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;
use SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum;
use SimpleSAML\Module\oidc\Entities\Interfaces\AccessTokenEntityInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\EntityStringRepresentationInterface;
use SimpleSAML\Module\oidc\Entities\Traits\AssociateWithAuthCodeTrait;
use SimpleSAML\Module\oidc\Entities\Traits\RevokeTokenTrait;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\JwtTypesEnum;
use SimpleSAML\OpenID\Jws;
use SimpleSAML\OpenID\Jws\ParsedJws;
use Stringable;

/**
 * @psalm-suppress PropertyNotSetInConstructor
 */
class AccessTokenEntity implements AccessTokenEntityInterface, EntityStringRepresentationInterface, Stringable
{
    use AccessTokenTrait;
    use TokenEntityTrait;
    use EntityTrait;
    use RevokeTokenTrait;
    use AssociateWithAuthCodeTrait;


    /**
     * String representation of access token issued to the client.
     * @var string|null $stringRepresentation
     */
    protected ?string $stringRepresentation = null;

    /**
     * Claims that were individual requested
     * @var array $requestedClaims
     */
    protected array $requestedClaims;


    /**
     * @param \League\OAuth2\Server\Entities\ScopeEntityInterface[] $scopes
     */
    public function __construct(
        string $id,
        OAuth2ClientEntityInterface $clientEntity,
        array $scopes,
        DateTimeImmutable $expiryDateTime,
        protected readonly Jws $jws,
        protected readonly ModuleConfig $moduleConfig,
        int|string|null $userIdentifier = null,
        ?string $authCodeId = null,
        ?array $requestedClaims = null,
        ?bool $isRevoked = false,
        protected readonly ?FlowTypeEnum $flowTypeEnum = null,
        protected readonly ?array $authorizationDetails = null,
        protected readonly ?string $boundClientId = null,
        protected readonly ?string $boundRedirectUri = null,
        protected readonly ?string $issuerState = null,
    ) {
        if ($id === '') {
            throw new InvalidArgumentException('Access token identifier cannot be empty.');
        }

        $this->setIdentifier($id);
        $this->setClient($clientEntity);
        foreach ($scopes as $scope) {
            $this->addScope($scope);
        }
        $this->setExpiryDateTime($expiryDateTime);
        if (!is_null($userIdentifier)) {
            $userIdentifier = (string)$userIdentifier;
        }
        if (!empty($userIdentifier)) {
            $this->setUserIdentifier($userIdentifier);
        }
        $this->setAuthCodeId($authCodeId);
        $this->setRequestedClaims($requestedClaims ?? []);
        if ($isRevoked) {
            $this->revoke();
        }
    }


    /**
     * @return array
     */
    public function getRequestedClaims(): array
    {
        return $this->requestedClaims;
    }


    public function setRequestedClaims(array $requestedClaims): void
    {
        $this->requestedClaims = $requestedClaims;
    }


    /**
     * {@inheritdoc}
     * @throws \JsonException
     */
    public function getState(): array
    {
        return [
            'id' => $this->getIdentifier(),
            'scopes' => json_encode($this->scopes, JSON_THROW_ON_ERROR),
            'expires_at' => $this->getExpiryDateTime()->format('Y-m-d H:i:s'),
            'user_id' => $this->getUserIdentifier(),
            'client_id' => $this->getClient()->getIdentifier(),
            'is_revoked' => $this->isRevoked(),
            'auth_code_id' => $this->getAuthCodeId(),
            'requested_claims' => json_encode($this->requestedClaims, JSON_THROW_ON_ERROR),
            'flow_type' => $this->flowTypeEnum?->value,
            'authorization_details' => is_array($this->authorizationDetails) ?
                json_encode($this->authorizationDetails, JSON_THROW_ON_ERROR) :
                null,
            'bound_client_id' => $this->boundClientId,
            'bound_redirect_uri' => $this->boundRedirectUri,
            'issuer_state' => $this->issuerState,
        ];
    }


    /**
     * Generate string representation, save it in a field, and return it.
     * @return string
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    public function __toString(): string
    {
        return $this->toString();
    }


    /**
     * Get string representation of access token at the moment of casting it to string.
     * @return string String representation of the access token.
     */
    public function toString(): string
    {
        return $this->stringRepresentation ??= $this->convertToJWT()->getToken();
    }


    /**
     * Implemented instead of original AccessTokenTrait::convertToJWT() method
     * in order to remove microseconds from timestamps and to add claims
     * like iss, etc.
     *
     * The token follows the shape of the JWT Profile for OAuth 2.0 Access Tokens (RFC 9068): "typ" header
     * (section 2.1), "client_id" (section 2.2) and the space-separated "scope" string (section 2.2.3,
     * RFC 8693 section 4.2). The "aud" claim stays the client identifier (resource indicators are not
     * implemented), and the "scopes" array is kept for consumers written against earlier versions.
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \Exception
     */
    protected function convertToJWT(): ParsedJws
    {
        $protocolSignatureKeyPair = $this->moduleConfig->getProtocolSignatureKeyPairBag()->getFirstOrFail();
        $currentTimestamp = $this->jws->helpers()->dateTime()->getUtc()->getTimestamp();
        $clientId = $this->getClient()->getIdentifier();
        $scopeIdentifiers = array_map(
            fn(ScopeEntityInterface $scope): string => $scope->getIdentifier(),
            $this->getScopes(),
        );

        // Omit only what is absent (no user, no scope, no issuer state); a valid value of "0" must survive.
        $payload = array_filter(
            [
                ClaimsEnum::Iss->value => $this->moduleConfig->getIssuer(),
                ClaimsEnum::Iat->value => $currentTimestamp,
                ClaimsEnum::Jti->value => $this->getIdentifier(),
                ClaimsEnum::Aud->value => $clientId,
                ClaimsEnum::Nbf->value => $currentTimestamp,
                ClaimsEnum::Exp->value => $this->expiryDateTime->getTimestamp(),
                ClaimsEnum::Sub->value => (string)$this->getUserIdentifier(),
                ClaimsEnum::ClientId->value => $clientId,
                ClaimsEnum::Scope->value => implode(' ', $scopeIdentifiers),
                'scopes' => $this->getScopes(),
                ClaimsEnum::IssuerState->value => $this->issuerState,
            ],
            fn(mixed $value): bool => $value !== null && $value !== '' && $value !== [],
        );

        $header = [
            ClaimsEnum::Kid->value => $protocolSignatureKeyPair->getKeyPair()->getKeyId(),
            ClaimsEnum::Typ->value => JwtTypesEnum::AtJwt->value,
        ];

        return $this->jws->parsedJwsFactory()->fromData(
            $protocolSignatureKeyPair->getKeyPair()->getPrivateKey(),
            $protocolSignatureKeyPair->getSignatureAlgorithm(),
            $payload,
            $header,
        );
    }


    public function getFlowTypeEnum(): ?FlowTypeEnum
    {
        return $this->flowTypeEnum;
    }


    public function getAuthorizationDetails(): ?array
    {
        return $this->authorizationDetails;
    }


    public function getBoundClientId(): ?string
    {
        return $this->boundClientId;
    }


    public function getBoundRedirectUri(): ?string
    {
        return $this->boundRedirectUri;
    }


    public function getIssuerState(): ?string
    {
        return $this->issuerState;
    }
}
