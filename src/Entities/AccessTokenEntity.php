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
use SimpleSAML\OpenID\OAuth2;
use SimpleSAML\OpenID\OAuth2\JwtAccessToken;
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
     * @param string|null $subject The subject the token was minted with (SubjectResolver): the 'sub' claim of the
     * JWT, of the ID token issued alongside and of the refresh token payload, so that all three name the End-User
     * the same way. Not persisted: null for an entity rehydrated from storage, whose JWT is never rebuilt.
     * @param array<non-empty-string, mixed> $userClaims The user claims placed in the JWT next to 'sub'
     * (AccessTokenClaimsResolver): the identity claims and the configured access token claims a granted scope
     * carries, as they were when the token was minted. Not persisted, for the same reason as the subject.
     */
    public function __construct(
        string $id,
        OAuth2ClientEntityInterface $clientEntity,
        array $scopes,
        DateTimeImmutable $expiryDateTime,
        protected readonly OAuth2 $oAuth2,
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
        protected readonly ?string $subject = null,
        protected readonly array $userClaims = [],
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
     * The subject resolved when the token was minted, or null for an entity built without one (rehydrated from
     * storage). The JWT itself always carries a 'sub', see convertToJWT().
     */
    public function getSubject(): ?string
    {
        return $this->subject;
    }


    /**
     * @return array<non-empty-string, mixed>
     */
    public function getUserClaims(): array
    {
        return $this->userClaims;
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
     * The token is a JWT Profile for OAuth 2.0 Access Tokens (RFC 9068) token, minted through the library's
     * JwtAccessTokenFactory: it writes the "typ" header (section 2.1) and validates the payload against the
     * profile before signing, so a token missing one of the REQUIRED claims of section 2.2, or carrying one
     * of a shape the profile does not give it (a "groups" which is not a list, say), is refused here rather
     * than by a resource server. This class supplies "client_id" (section 2.2) and the space-separated
     * "scope" string (section 2.2.3, RFC 8693 section 4.2). The "aud" claim stays the client identifier
     * (resource indicators are not implemented), and the "scopes" array is kept for consumers written
     * against earlier versions.
     *
     * The user claims come first and the envelope is written over them: a user claim can never overwrite
     * "iss", "sub", "aud", "client_id", "scope" ... whatever the configuration says (ModuleConfig refuses
     * those names as well; this is the second line).
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException On a payload the profile does not allow.
     * @throws \Exception
     */
    protected function convertToJWT(): JwtAccessToken
    {
        $protocolSignatureKeyPair = $this->moduleConfig->getProtocolSignatureKeyPairBag()->getFirstOrFail();
        $currentTimestamp = $this->oAuth2->helpers()->dateTime()->getUtc()->getTimestamp();
        $clientId = $this->getClient()->getIdentifier();
        $scopeIdentifiers = array_map(
            fn(ScopeEntityInterface $scope): string => $scope->getIdentifier(),
            $this->getScopes(),
        );

        // Omit only what is absent (no scope, no issuer state); a valid value of "0" must survive.
        $envelope = array_filter(
            [
                ClaimsEnum::Iss->value => $this->moduleConfig->getIssuer(),
                ClaimsEnum::Iat->value => $currentTimestamp,
                ClaimsEnum::Jti->value => $this->getIdentifier(),
                ClaimsEnum::Aud->value => $clientId,
                ClaimsEnum::Nbf->value => $currentTimestamp,
                ClaimsEnum::Exp->value => $this->expiryDateTime->getTimestamp(),
                ClaimsEnum::ClientId->value => $clientId,
                ClaimsEnum::Scope->value => implode(' ', $scopeIdentifiers),
                'scopes' => $this->getScopes(),
                ClaimsEnum::IssuerState->value => $this->issuerState,
            ],
            fn(mixed $value): bool => $value !== null && $value !== '' && $value !== [],
        );

        // "sub" is REQUIRED (RFC 9068 section 2.2): the subject resolved at minting, else the internal user
        // identifier for an entity built without one, else -- no resource owner involved -- the client itself:
        // "the value of "sub" SHOULD correspond to an identifier the authorization server uses to indicate the
        // client application". Set after the filter above, so a valid subject of "0" is kept.
        $envelope[ClaimsEnum::Sub->value] = $this->subject ?? $this->getUserIdentifier() ?? $clientId;

        // User claims keep a valid falsy value too (no filter), which is why they are not part of the list above.
        $payload = array_merge($this->userClaims, $envelope);

        // The factory writes the "typ" header itself (at+jwt), whatever is given here.
        $header = [
            ClaimsEnum::Kid->value => $protocolSignatureKeyPair->getKeyPair()->getKeyId(),
        ];

        return $this->oAuth2->jwtAccessTokenFactory()->fromData(
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
