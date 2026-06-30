<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories\Entities;

use DateTimeImmutable;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Codebooks\RegistrationTypeEnum;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Utils\ResponseTypeGrantTypeCorrespondence;
use SimpleSAML\OpenID\Codebooks\ApplicationTypesEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\GrantTypesEnum;
use SimpleSAML\OpenID\Codebooks\ResponseTypesEnum;
use SimpleSAML\OpenID\Codebooks\ScopesEnum;
use SimpleSAML\OpenID\Codebooks\TokenEndpointAuthMethodsEnum;

class ClientEntityFactory
{
    /**
     * Informational ("store & echo") client metadata that is persisted as-is
     * into the extra metadata blob when present in registration data, so it
     * can be echoed back in registration/read responses. These carry no
     * behavioral enforcement on the OP. Format/security validation
     * (and impersonation protection) happens at the registration boundary;
     * see \SimpleSAML\Module\oidc\Server\Registration\ClientMetadataValidator.
     *
     * @var string[]
     */
    public const array STORE_AND_ECHO_METADATA_KEYS = [
        ClaimsEnum::LogoUri->value,
        ClaimsEnum::ClientUri->value,
        ClaimsEnum::PolicyUri->value,
        ClaimsEnum::TosUri->value,
        ClaimsEnum::Contacts->value,
        ClaimsEnum::ApplicationType->value,
        ClaimsEnum::InitiateLoginUri->value,
        ClaimsEnum::SoftwareId->value,
        ClaimsEnum::SoftwareVersion->value,
    ];

    public function __construct(
        private readonly SspBridge $sspBridge,
        private readonly Helpers $helpers,
        private readonly ModuleConfig $moduleConfig,
    ) {
    }

    /**
     * @param string[] $redirectUri
     * @param string[] $scopes
     * @param string[] $postLogoutRedirectUri
     * @param string[] $clientRegistrationTypes
     * @param array[] $federationJwks
     * @param array[] $jwks
     */
    public function fromData(
        string $id,
        string $secret,
        string $name,
        string $description,
        array $redirectUri,
        array $scopes,
        bool $isEnabled,
        bool $isConfidential = false,
        ?string $authSource = null,
        ?string $owner = null,
        array $postLogoutRedirectUri = [],
        ?string $backChannelLogoutUri = null,
        ?string $entityIdentifier = null,
        ?array $clientRegistrationTypes = null,
        ?array $federationJwks = null,
        ?array $jwks = null,
        ?string $jwksUri = null,
        ?string $signedJwksUri = null,
        RegistrationTypeEnum $registrationType = RegistrationTypeEnum::Manual,
        ?DateTimeImmutable $updatedAt = null,
        ?DateTimeImmutable $createdAt = null,
        ?DateTimeImmutable $expiresAt = null,
        bool $isGeneric = false,
        ?array $extraMetadata = null,
        ?string $registrationAccessToken = null,
    ): ClientEntityInterface {
        return new ClientEntity(
            $id,
            $secret,
            $name,
            $description,
            $redirectUri,
            $scopes,
            $isEnabled,
            $isConfidential,
            $authSource,
            $owner,
            $postLogoutRedirectUri,
            $backChannelLogoutUri,
            $entityIdentifier,
            $clientRegistrationTypes,
            $federationJwks,
            $jwks,
            $jwksUri,
            $signedJwksUri,
            $registrationType,
            $updatedAt,
            $createdAt,
            $expiresAt,
            $isGeneric,
            $extraMetadata,
            $registrationAccessToken,
        );
    }

    /**
     * Resolve client data from registration metadata.
     *
     * @param array[] $federationJwks
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \SimpleSAML\Error\ConfigurationError
     * @psalm-suppress MixedAssignment
     */
    public function fromRegistrationData(
        array $metadata,
        RegistrationTypeEnum $registrationType,
        ?DateTimeImmutable $expiresAt = null,
        ?ClientEntityInterface $existingClient = null,
        ?string $clientIdentifier = null,
        ?array $federationJwks = null,
    ): ClientEntityInterface {
        // Security: scrub administrator-only properties from client-supplied
        // registration metadata.
        //
        // This method builds clients from metadata provided by a remote party,
        // i.e. through OIDC Dynamic Client Registration (RFC 7591) or OpenID
        // Federation (explicit / automatic) registration. Some client properties
        // must never be controllable by the registering party, because honoring
        // them would let an untrusted client influence server-side behavior. The
        // prime example is `authproc` (per-client Authentication Processing
        // Filters): a filter entry names a PHP class that is instantiated and
        // executed on the OP during authentication, so accepting it from
        // registration metadata would be a remote code execution vector.
        //
        // Such properties are settable ONLY by a trusted administrator, via the
        // admin UI / API (ClientEntityFactory::fromData()). We strip every
        // deny-listed key from the incoming metadata here, so it can neither be
        // read below nor leak into a future code path. Any value an administrator
        // has already set on an existing client is preserved because it is
        // carried over from $existingClient->getExtraMetadata() further down (it
        // does not come from $metadata).
        //
        // The deny-list itself lives next to the property definitions, in
        // ClientEntity::ADMIN_ONLY_METADATA_KEYS.
        foreach (ClientEntity::ADMIN_ONLY_METADATA_KEYS as $adminOnlyMetadataKey) {
            unset($metadata[$adminOnlyMetadataKey]);
        }

        // RFC 7592 client update is a full REPLACE, not a merge: on a DCR update, client-settable metadata the
        // request omits must be reset to its OP default (or removed), while server-managed and admin-only
        // properties are still carried over from the existing client. We model that with a separate "metadata
        // fallback" client that is null on a DCR update, so the per-field `?? $metadataFallbackClient?->...`
        // expressions below fall back to the default rather than the previously-registered value. Manual and
        // OpenID Federation registrations keep their existing merge behaviour (the entity statement / admin form
        // carries the full intended state anyway).
        $isDcrUpdate = $existingClient !== null && $registrationType === RegistrationTypeEnum::Dynamic;
        $metadataFallbackClient = $isDcrUpdate ? null : $existingClient;

        $id = $clientIdentifier ?: $existingClient?->getIdentifier();
        if (empty($id)) {
            $id = $this->sspBridge->utils()->random()->generateID();
        }

        $secret = $existingClient?->getSecret() ?? $this->sspBridge->utils()->random()->generateID();

        $name = (string)($metadata[ClaimsEnum::ClientName->value] ?? $metadataFallbackClient?->getName() ?? $id);

        $description = $existingClient?->getDescription() ?? '';

        $authSource = $existingClient?->getAuthSourceId();

        (isset($metadata[ClaimsEnum::RedirectUris->value]) && is_array($metadata[ClaimsEnum::RedirectUris->value])) ||
        throw OidcServerException::accessDenied('redirect URIs missing');
        $redirectUris = $this->helpers->arr()->ensureStringValues($metadata[ClaimsEnum::RedirectUris->value]);

        // Resolve the requested scopes: from this request's metadata, falling back to an existing client's scopes
        // (e.g. on a DCR update that omits `scope`). null here means scopes were genuinely not specified.
        $requestedScopes = $metadata[ClaimsEnum::Scope->value] ?? $metadataFallbackClient?->getScopes();
        if ($requestedScopes === null) {
            // No scope was specified. For Dynamic Client Registration, assign the configured default scope set
            // (OIDC DCR 1.0 lets the OP assign a default set). Manual and OpenID Federation automatic registrations
            // keep the conservative `openid`-only default. Note: an explicit but unsupported `scope` is NOT treated
            // as "not specified" - it falls through to the supported-scope filter below and ends up as `openid` only.
            $scopes = $registrationType === RegistrationTypeEnum::Dynamic
            ? $this->moduleConfig->getDcrDefaultScopes()
            : [ScopesEnum::OpenId->value];
        } else {
            $scopes = is_array($requestedScopes) ? $this->helpers->arr()->ensureStringValues($requestedScopes) :
            $this->helpers->str()->convertScopesStringToArray((string)$requestedScopes);
        }
        // Filter to only allowed scopes
        $scopes = array_filter(
            $scopes,
            fn(string $scope): bool => array_key_exists($scope, $this->moduleConfig->getScopes()),
        );
        // Let's ensure there is at least 'openid' scope present.
        $scopes = empty($scopes) ? [ScopesEnum::OpenId->value] : $scopes;

        // For a new Dynamic (DCR) client, the initial enabled state is governed by configuration: deployments can
        // choose to create dynamically registered clients disabled, so an administrator reviews and enables them
        // before use ("register, then approve"). On update the existing state is preserved (review only gates the
        // initial registration). OpenID Federation automatic registrations are always created enabled.
        $isEnabled = $existingClient?->isEnabled()
        ?? ($registrationType === RegistrationTypeEnum::Dynamic
                ? $this->moduleConfig->getDcrRegisteredClientsEnabled()
                : true);

        $isConfidential = $metadataFallbackClient?->isConfidential() ?? $this->determineIsConfidential(
            $metadata,
        );

        $owner = $existingClient?->getOwner();

        $postLogoutRedirectUris = isset($metadata[ClaimsEnum::PostLogoutRedirectUris->value]) &&
        is_array($metadata[ClaimsEnum::PostLogoutRedirectUris->value]) ?
        $this->helpers->arr()->ensureStringValues($metadata[ClaimsEnum::PostLogoutRedirectUris->value]) :
        $metadataFallbackClient?->getPostLogoutRedirectUri() ?? [];

        $backChannelLogoutUri = isset($metadata[ClaimsEnum::BackChannelLogoutUri->value]) &&
        is_string($metadata[ClaimsEnum::BackChannelLogoutUri->value]) ?
        $metadata[ClaimsEnum::BackChannelLogoutUri->value] :
        $metadataFallbackClient?->getBackChannelLogoutUri();

        $entityIdentifier = $clientIdentifier ?? $existingClient?->getEntityIdentifier();

        $clientRegistrationTypes = isset($metadata[ClaimsEnum::ClientRegistrationTypes->value]) &&
        is_array($metadata[ClaimsEnum::ClientRegistrationTypes->value]) ?
        $this->helpers->arr()->ensureStringValues($metadata[ClaimsEnum::ClientRegistrationTypes->value]) :
        $metadataFallbackClient?->getClientRegistrationTypes();

        $federationJwks = $federationJwks ?? $metadataFallbackClient?->getFederationJwks();

        /** @var ?array[] $jwks */
        $jwks = isset($metadata[ClaimsEnum::Jwks->value]) &&
        is_array($metadata[ClaimsEnum::Jwks->value]) &&
        array_key_exists(ClaimsEnum::Keys->value, $metadata[ClaimsEnum::Jwks->value]) &&
        (!empty($metadata[ClaimsEnum::Jwks->value][ClaimsEnum::Keys->value])) ?
        $metadata[ClaimsEnum::Jwks->value] :
        $metadataFallbackClient?->getJwks();

        $jwksUri = isset($metadata[ClaimsEnum::JwksUri->value]) &&
        is_string($metadata[ClaimsEnum::JwksUri->value]) ?
        $metadata[ClaimsEnum::JwksUri->value] :
        $metadataFallbackClient?->getJwksUri();

        $signedJwksUri = isset($metadata[ClaimsEnum::SignedJwksUri->value]) &&
        is_string($metadata[ClaimsEnum::SignedJwksUri->value]) ?
        $metadata[ClaimsEnum::SignedJwksUri->value] :
        $metadataFallbackClient?->getSignedJwksUri();

//        $registrationType = $registrationType;

        $updatedAt = $this->helpers->dateTime()->getUtc();

        $createdAt = $existingClient ? $existingClient->getCreatedAt() : $updatedAt;

//        $expiresAt = $expiresAt;

        $isGeneric = $existingClient?->isGeneric() ?? false;

        // Carry over any Registration Access Token hash from an existing client. For a newly registered client this
        // is null here; the registration controller generates and assigns the token after building the entity.
        $registrationAccessToken = $existingClient?->getRegistrationAccessTokenHash();

        // On a DCR update this starts empty (replace semantics); on create/manual/federation it carries the existing
        // extra metadata. Admin-only extra metadata (e.g. authproc) is never client-settable and is re-injected from
        // the real existing client below so a DCR update cannot drop it.
        $extraMetadata = $metadataFallbackClient?->getExtraMetadata() ?? [];
        if ($isDcrUpdate) {
            // $isDcrUpdate implies $existingClient is non-null (see its definition above).
            $existingExtraMetadata = $existingClient->getExtraMetadata();
            foreach (ClientEntity::ADMIN_ONLY_METADATA_KEYS as $adminOnlyMetadataKey) {
                if (array_key_exists($adminOnlyMetadataKey, $existingExtraMetadata)) {
                    /** @psalm-suppress MixedAssignment */
                    $extraMetadata[$adminOnlyMetadataKey] = $existingExtraMetadata[$adminOnlyMetadataKey];
                }
            }
        }

        // Handle any other supported client metadata as extra metadata.
        // id_token_signed_response_alg
        $idTokenSignedResponseAlg = isset($metadata[ClaimsEnum::IdTokenSignedResponseAlg->value]) &&
        is_string($metadata[ClaimsEnum::IdTokenSignedResponseAlg->value]) ?
        $metadata[ClaimsEnum::IdTokenSignedResponseAlg->value] :
        $metadataFallbackClient?->getIdTokenSignedResponseAlg();

        // Make sure the requested id_token_signed_response_alg is one of the OP
        // can actually sign ID Tokens with, i.e. one for which a protocol
        // signing key pair is configured (the same set advertised as
        // id_token_signing_alg_values_supported in OP metadata). Otherwise,
        // ID Token building would fail later during an authentication flow.
        if (is_string($idTokenSignedResponseAlg)) {
            $supportedIdTokenSigningAlgs = $this->moduleConfig
                ->getProtocolSignatureKeyPairBag()
                ->getAllAlgorithmNamesUnique();

            in_array($idTokenSignedResponseAlg, $supportedIdTokenSigningAlgs, true) ||
            throw OidcServerException::invalidClientMetadata(sprintf(
                'Unsupported id_token_signed_response_alg "%s". Supported values: %s.',
                $idTokenSignedResponseAlg,
                implode(', ', $supportedIdTokenSigningAlgs),
            ));
        }

        $extraMetadata[ClaimsEnum::IdTokenSignedResponseAlg->value] = $idTokenSignedResponseAlg;

        // request_uris: persisted into extra metadata so that Request Objects passed by reference (request_uri,
        // RFC 9101) can be exact-matched at the authorization endpoint when require_request_uri_registration is on
        // (see ClientEntity::getRequestUris() and RequestParamsResolver::isHttpsRequestUriFetchAllowed()). Unlike
        // the store-and-echo keys below this one IS behaviorally enforced. When omitted on update, any existing
        // value is preserved (it is already carried over from the existing client's extra metadata above).
        if (
            isset($metadata[ClaimsEnum::RequestUris->value]) &&
            is_array($metadata[ClaimsEnum::RequestUris->value])
        ) {
            $extraMetadata[ClaimsEnum::RequestUris->value] = $this->helpers->arr()->ensureStringValues(
                $metadata[ClaimsEnum::RequestUris->value],
            );
        }

        // grant_types / response_types / token_endpoint_auth_method: persisted so they can be returned in the
        // registration response (RFC 7591 Section 3.2.1) and, going forward, enforced. For Dynamic registrations
        // the OIDC DCR 1.0 defaults are applied when the client does not provide them; manual and federation
        // registrations are left untouched (any existing value is carried over from the existing client above).
        if (isset($metadata[ClaimsEnum::GrantTypes->value]) && is_array($metadata[ClaimsEnum::GrantTypes->value])) {
            $extraMetadata[ClaimsEnum::GrantTypes->value] = $this->helpers->arr()->ensureStringValues(
                $metadata[ClaimsEnum::GrantTypes->value],
            );
        } elseif (
            $registrationType === RegistrationTypeEnum::Dynamic &&
            !array_key_exists(ClaimsEnum::GrantTypes->value, $extraMetadata)
        ) {
            $extraMetadata[ClaimsEnum::GrantTypes->value] = [GrantTypesEnum::AuthorizationCode->value];
        }

        if (
            isset($metadata[ClaimsEnum::ResponseTypes->value]) &&
            is_array($metadata[ClaimsEnum::ResponseTypes->value])
        ) {
            $extraMetadata[ClaimsEnum::ResponseTypes->value] = $this->helpers->arr()->ensureStringValues(
                $metadata[ClaimsEnum::ResponseTypes->value],
            );
        } elseif (
            $registrationType === RegistrationTypeEnum::Dynamic &&
            !array_key_exists(ClaimsEnum::ResponseTypes->value, $extraMetadata)
        ) {
            $extraMetadata[ClaimsEnum::ResponseTypes->value] = [ResponseTypesEnum::Code->value];
        }

        // Normalize grant_types to satisfy the OIDC DCR response_type <-> grant_type correspondence: every grant
        // type required by a registered response_type MUST be present in grant_types. We augment rather than reject,
        // so a client that (legally) omits grant_types while declaring a non-code response_type still ends up with a
        // consistent, usable registration (echoed back per RFC 7591 Section 3.2.1). Only applied when grant_types is
        // already present (Dynamic clients always are, after the default above); federation/manual registrations
        // without a grant_types value are left untouched (presence-based, like the per-client enforcement).
        if (
            array_key_exists(ClaimsEnum::GrantTypes->value, $extraMetadata) &&
            is_array($extraMetadata[ClaimsEnum::GrantTypes->value]) &&
            array_key_exists(ClaimsEnum::ResponseTypes->value, $extraMetadata) &&
            is_array($extraMetadata[ClaimsEnum::ResponseTypes->value])
        ) {
            $extraMetadata[ClaimsEnum::GrantTypes->value] =
            ResponseTypeGrantTypeCorrespondence::mergeRequiredGrantTypes(
                $this->helpers->arr()->ensureStringValues($extraMetadata[ClaimsEnum::GrantTypes->value]),
                $this->helpers->arr()->ensureStringValues($extraMetadata[ClaimsEnum::ResponseTypes->value]),
            );
        }

        if (
            isset($metadata[ClaimsEnum::TokenEndpointAuthMethod->value]) &&
            is_string($metadata[ClaimsEnum::TokenEndpointAuthMethod->value])
        ) {
            $extraMetadata[ClaimsEnum::TokenEndpointAuthMethod->value] =
            $metadata[ClaimsEnum::TokenEndpointAuthMethod->value];
        } elseif (
            $registrationType === RegistrationTypeEnum::Dynamic &&
            !array_key_exists(ClaimsEnum::TokenEndpointAuthMethod->value, $extraMetadata)
        ) {
            $extraMetadata[ClaimsEnum::TokenEndpointAuthMethod->value] = $isConfidential ?
            TokenEndpointAuthMethodsEnum::ClientSecretBasic->value :
            TokenEndpointAuthMethodsEnum::None->value;
        }

        // Keep the client type (confidential/public) in lockstep with the effective token_endpoint_auth_method,
        // which is the DCR signal for it: `none` => public, any real authentication method => confidential. This is
        // re-derived from the final resolved value (provided, carried over from an existing client, or defaulted
        // above), so it stays correct on RFC 7592 updates too - not just first registration. When no auth method is
        // resolved (e.g. a federation/manual registration that did not set one), the value determined earlier from
        // the rest of the metadata (or carried over from the existing client) stands.
        $effectiveTokenEndpointAuthMethod = $extraMetadata[ClaimsEnum::TokenEndpointAuthMethod->value] ?? null;
        if (is_string($effectiveTokenEndpointAuthMethod) && $effectiveTokenEndpointAuthMethod !== '') {
            $isConfidential = $effectiveTokenEndpointAuthMethod !== TokenEndpointAuthMethodsEnum::None->value;
        }

        // Behavioral "default when omitted" metadata, persisted (and enforced in the authorization flow / ID Token).
        // Values are already format-validated at the registration boundary (ClientMetadataValidator) and the admin
        // form; here we only persist when present so they can be echoed and applied. Preserved on update when omitted.
        if (array_key_exists(ClaimsEnum::DefaultMaxAge->value, $metadata)) {
            /** @var mixed $defaultMaxAge */
            $defaultMaxAge = $metadata[ClaimsEnum::DefaultMaxAge->value];
            if (is_int($defaultMaxAge) || (is_string($defaultMaxAge) && ctype_digit($defaultMaxAge))) {
                $extraMetadata[ClaimsEnum::DefaultMaxAge->value] = (int)$defaultMaxAge;
            }
        }

        if (array_key_exists(ClaimsEnum::RequireAuthTime->value, $metadata)) {
            $extraMetadata[ClaimsEnum::RequireAuthTime->value] = (bool)$metadata[ClaimsEnum::RequireAuthTime->value];
        }

        if (
            isset($metadata[ClaimsEnum::DefaultAcrValues->value]) &&
            is_array($metadata[ClaimsEnum::DefaultAcrValues->value])
        ) {
            $extraMetadata[ClaimsEnum::DefaultAcrValues->value] = $this->helpers->arr()->ensureStringValues(
                $metadata[ClaimsEnum::DefaultAcrValues->value],
            );
        }

        // Persist informational ("store & echo") metadata so it can be returned in registration/read responses.
        foreach (self::STORE_AND_ECHO_METADATA_KEYS as $storeAndEchoKey) {
            if (array_key_exists($storeAndEchoKey, $metadata)) {
                /** @psalm-suppress MixedAssignment */
                $extraMetadata[$storeAndEchoKey] = $metadata[$storeAndEchoKey];
            }
        }

        return $this->fromData(
            $id,
            $secret,
            $name,
            $description,
            $redirectUris,
            $scopes,
            $isEnabled,
            $isConfidential,
            $authSource,
            $owner,
            $postLogoutRedirectUris,
            $backChannelLogoutUri,
            $entityIdentifier,
            $clientRegistrationTypes,
            $federationJwks,
            $jwks,
            $jwksUri,
            $signedJwksUri,
            $registrationType,
            $updatedAt,
            $createdAt,
            $expiresAt,
            $isGeneric,
            $extraMetadata,
            $registrationAccessToken,
        );
    }

    protected function determineIsConfidential(
        array $metadata,
    ): bool {
        if (
            array_key_exists(ClaimsEnum::ApplicationType->value, $metadata) &&
            $metadata[ClaimsEnum::ApplicationType->value] === ApplicationTypesEnum::Native->value
        ) {
            // Native application type is strong indication of public client.
            return false;
        }

        if (
            array_key_exists(ClaimsEnum::TokenEndpointAuthMethod->value, $metadata) &&
            $metadata[ClaimsEnum::TokenEndpointAuthMethod->value] === TokenEndpointAuthMethodsEnum::None->value
        ) {
            // Value 'none' for token auth method is strong indication of public client.
            return false;
        }

        if (
            array_key_exists(ClaimsEnum::GrantTypes->value, $metadata) &&
            is_array($metadata[ClaimsEnum::GrantTypes->value]) &&
            in_array(GrantTypesEnum::Implicit->value, $metadata[ClaimsEnum::GrantTypes->value], true)
        ) {
            // Explicit statement of implicit grant type is indication of public client.
            return false;
        }

        if (
            array_key_exists(ClaimsEnum::ResponseTypes->value, $metadata) &&
            is_array($metadata[ClaimsEnum::ResponseTypes->value]) &&
            (in_array(ResponseTypesEnum::IdToken->value, $metadata[ClaimsEnum::ResponseTypes->value], true) ||
                in_array(ResponseTypesEnum::IdTokenToken->value, $metadata[ClaimsEnum::ResponseTypes->value], true))
        ) {
            // Response type 'id_token' or 'id_token token' is indication of public client.
            return false;
        }

        // Assume confidential client.
        return true;
    }

    /**
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function fromState(array $state): ClientEntityInterface
    {
        if (
            !is_string($state[ClientEntity::KEY_ID]) ||
            !is_string($state[ClientEntity::KEY_SECRET]) ||
            !is_string($state[ClientEntity::KEY_NAME]) ||
            !is_string($state[ClientEntity::KEY_REDIRECT_URI]) ||
            !is_string($state[ClientEntity::KEY_SCOPES]) ||
            !is_string($state[ClientEntity::KEY_REGISTRATION_TYPE])
        ) {
            throw OidcServerException::serverError('Invalid Client Entity state');
        }

        $id = $state[ClientEntity::KEY_ID];
        $secret = $state[ClientEntity::KEY_SECRET];
        $name = $state[ClientEntity::KEY_NAME];
        $description = (string)($state[ClientEntity::KEY_DESCRIPTION] ?? '');

        /** @var string[] $redirectUris */
        $redirectUris = json_decode($state[ClientEntity::KEY_REDIRECT_URI], true, 512, JSON_THROW_ON_ERROR);

        /** @var string[] $scopes */
        $scopes = json_decode($state[ClientEntity::KEY_SCOPES], true, 512, JSON_THROW_ON_ERROR);

        $isEnabled = (bool) $state[ClientEntity::KEY_IS_ENABLED];

        $isConfidential = (bool) ($state[ClientEntity::KEY_IS_CONFIDENTIAL] ?? false);

        $authSource = empty($state[ClientEntity::KEY_AUTH_SOURCE]) ?
        null :
        (string)$state[ClientEntity::KEY_AUTH_SOURCE];

        $owner = empty($state[ClientEntity::KEY_OWNER]) ? null : (string)$state[ClientEntity::KEY_OWNER];

        /** @var string[] $postLogoutRedirectUris */
        $postLogoutRedirectUris = json_decode(
            (string)($state[ClientEntity::KEY_POST_LOGOUT_REDIRECT_URI] ?? "[]"),
            true,
            512,
            JSON_THROW_ON_ERROR,
        );

        $backChannelLogoutUri = empty($state[ClientEntity::KEY_BACKCHANNEL_LOGOUT_URI]) ?
        null :
        (string)$state[ClientEntity::KEY_BACKCHANNEL_LOGOUT_URI];

        $entityIdentifier = empty($state[ClientEntity::KEY_ENTITY_IDENTIFIER]) ?
        null :
        (string)$state[ClientEntity::KEY_ENTITY_IDENTIFIER];

        /** @var ?string[] $clientRegistrationTypes */
        $clientRegistrationTypes = empty($state[ClientEntity::KEY_CLIENT_REGISTRATION_TYPES]) ?
        null :
        json_decode((string)$state[ClientEntity::KEY_CLIENT_REGISTRATION_TYPES], true, 512, JSON_THROW_ON_ERROR);

        /** @var ?array[] $federationJwks */
        $federationJwks = empty($state[ClientEntity::KEY_FEDERATION_JWKS]) ?
        null :
        json_decode((string)$state[ClientEntity::KEY_FEDERATION_JWKS], true, 512, JSON_THROW_ON_ERROR);

        /** @var ?array[] $jwks */
        $jwks = empty($state[ClientEntity::KEY_JWKS]) ?
        null :
        json_decode((string)$state[ClientEntity::KEY_JWKS], true, 512, JSON_THROW_ON_ERROR);

        $jwksUri = empty($state[ClientEntity::KEY_JWKS_URI]) ? null : (string)$state[ClientEntity::KEY_JWKS_URI];
        $signedJwksUri = empty($state[ClientEntity::KEY_SIGNED_JWKS_URI]) ?
        null :
        (string)$state[ClientEntity::KEY_SIGNED_JWKS_URI];

        $registrationType = RegistrationTypeEnum::from(trim($state[ClientEntity::KEY_REGISTRATION_TYPE]));

        $updatedAt = empty($state[ClientEntity::KEY_UPDATED_AT]) ? null :
        $this->helpers->dateTime()->getUtc((string)$state[ClientEntity::KEY_UPDATED_AT]);
        $createdAt = empty($state[ClientEntity::KEY_CREATED_AT]) ? null :
        $this->helpers->dateTime()->getUtc((string)$state[ClientEntity::KEY_CREATED_AT]);
        $expiresAt = empty($state[ClientEntity::KEY_EXPIRES_AT]) ? null :
        $this->helpers->dateTime()->getUtc((string)$state[ClientEntity::KEY_EXPIRES_AT]);

        $isGeneric = (bool)$state[ClientEntity::KEY_IS_GENERIC];

        /** @var ?mixed[] $extraMetadata */
        $extraMetadata = empty($state[ClientEntity::KEY_EXTRA_METADATA]) ?
        null :
        json_decode((string)$state[ClientEntity::KEY_EXTRA_METADATA], true, 512, JSON_THROW_ON_ERROR);

        $registrationAccessToken = empty($state[ClientEntity::KEY_REGISTRATION_ACCESS_TOKEN]) ?
        null :
        (string)$state[ClientEntity::KEY_REGISTRATION_ACCESS_TOKEN];

        return $this->fromData(
            $id,
            $secret,
            $name,
            $description,
            $redirectUris,
            $scopes,
            $isEnabled,
            $isConfidential,
            $authSource,
            $owner,
            $postLogoutRedirectUris,
            $backChannelLogoutUri,
            $entityIdentifier,
            $clientRegistrationTypes,
            $federationJwks,
            $jwks,
            $jwksUri,
            $signedJwksUri,
            $registrationType,
            $updatedAt,
            $createdAt,
            $expiresAt,
            $isGeneric,
            $extraMetadata,
            $registrationAccessToken,
        );
    }

    public function getGenericForVci(): ClientEntityInterface
    {
        $clientId = 'vci_' .
        hash('sha256', 'vci_'  . $this->moduleConfig->sspConfig()->getString('secretsalt'));

        $clientSecret = $this->helpers->random()->getIdentifier();

        $credentialConfigurationIdsSupported = $this->moduleConfig->getVciCredentialConfigurationIdsSupported();

        $createdAt = $this->helpers->dateTime()->getUtc();

        return $this->fromData(
            id: $clientId,
            secret: $clientSecret,
            name: 'VCI Generic Client',
            description: 'Generic client for Verifiable Credential Issuance flows.',
            redirectUri: ['openid-credential-offer://'],
            scopes: ['openid', ...$credentialConfigurationIdsSupported],
            isEnabled: true,
            updatedAt: $createdAt,
            createdAt: $createdAt,
            isGeneric: true,
        );
    }
}
