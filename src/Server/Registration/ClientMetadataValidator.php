<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\Registration;

use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Utils\ResponseTypeGrantTypeCorrespondence;
use SimpleSAML\OpenID\Codebooks\ApplicationTypesEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\GrantTypesEnum;
use SimpleSAML\OpenID\Network\DestinationPolicy;

/**
 * Validates client-supplied registration metadata for the OpenID Connect Dynamic Client Registration endpoint.
 *
 * This runs only on the DCR path (the registration controller), not on the OpenID Federation automatic registration
 * path: the rules here (notably impersonation protection) are governed by DCR-specific configuration, whereas
 * federated clients are vouched for by their trust chain.
 *
 * The validator rejects on any violation (it does not silently substitute values), per the chosen policy. The
 * spec permits the OP to reject or substitute any field except redirect_uris.
 */
class ClientMetadataValidator
{
    /**
     * Informational URI metadata that, when impersonation protection is enabled, must share a host with one of the
     * registered redirect_uris. client_uri is intentionally excluded (it is the RP home page, legitimately on a
     * different marketing domain; the spec names only logo_uri and policy_uri).
     */
    private const array IMPERSONATION_PROTECTED_URI_CLAIMS = [
        ClaimsEnum::LogoUri->value,
        ClaimsEnum::PolicyUri->value,
        ClaimsEnum::TosUri->value,
    ];

    /**
     * All URI metadata fields whose format is validated.
     */
    private const array URI_CLAIMS = [
        ClaimsEnum::LogoUri->value,
        ClaimsEnum::ClientUri->value,
        ClaimsEnum::PolicyUri->value,
        ClaimsEnum::TosUri->value,
    ];

    // Front-channel logout metadata (not modelled in ClaimsEnum; this OP only supports back-channel logout).
    private const string CLAIM_FRONTCHANNEL_LOGOUT_URI = 'frontchannel_logout_uri';
    private const string CLAIM_FRONTCHANNEL_LOGOUT_SESSION_REQUIRED = 'frontchannel_logout_session_required';

    /**
     * Metadata for features this OP does not support. When a client requests any of these, registration is
     * rejected with invalid_client_metadata rather than silently ignored (which would leave the client behaving
     * differently than it asked). Map of metadata field => human description for the error hint.
     */
    private const array UNSUPPORTED_FEATURE_CLAIMS = [
        ClaimsEnum::SectorIdentifierUri->value =>
            'sector_identifier_uri (pairwise subject identifiers are not supported)',
        ClaimsEnum::UserinfoSignedResponseAlg->value =>
            'userinfo_signed_response_alg (signed UserInfo responses are not supported)',
        ClaimsEnum::UserinfoEncryptedResponseAlg->value =>
            'userinfo_encrypted_response_alg (encrypted UserInfo responses are not supported)',
        ClaimsEnum::UserinfoEncryptedResponseEnc->value =>
            'userinfo_encrypted_response_enc (encrypted UserInfo responses are not supported)',
        ClaimsEnum::IdTokenEncryptedResponseAlg->value =>
            'id_token_encrypted_response_alg (encrypted ID Tokens are not supported)',
        ClaimsEnum::IdTokenEncryptedResponseEnc->value =>
            'id_token_encrypted_response_enc (encrypted ID Tokens are not supported)',
        ClaimsEnum::RequestObjectEncryptionAlg->value =>
            'request_object_encryption_alg (encrypted Request Objects are not supported)',
        ClaimsEnum::RequestObjectEncryptionEnc->value =>
            'request_object_encryption_enc (encrypted Request Objects are not supported)',
        self::CLAIM_FRONTCHANNEL_LOGOUT_URI => 'frontchannel_logout_uri (front-channel logout is not supported)',
    ];

    /**
     * Metadata claims naming a destination this OP will later fetch from, as opposed to one it only shows
     * to a human or redirects a browser to. Only these are subject to the outbound destination policy.
     *
     * @var list<string>
     */
    private const array FETCHED_URI_CLAIMS = [
        ClaimsEnum::JwksUri->value,
        ClaimsEnum::SignedJwksUri->value,
        ClaimsEnum::BackChannelLogoutUri->value,
    ];

    /**
     * How many `request_uris` a client may register.
     *
     * Each distinct destination costs a synchronous DNS lookup during validation, so an unbounded list is
     * work an unauthenticated caller can order for itself: with registration open, one request carrying
     * thousands of unique names holds a worker for as long as the resolver takes to answer or time out on
     * every one of them. A client legitimately publishes a handful of Request Object locations; anything
     * near this bound is not a real deployment.
     */
    private const int MAX_REQUEST_URIS = 20;

    public function __construct(
        private readonly ModuleConfig $moduleConfig,
        private readonly DestinationPolicy $destinationPolicy,
    ) {
    }

    /**
     * Validate the incoming registration metadata. Returns the metadata unchanged on success.
     *
     * @param array $metadata
     * @param bool $isCallerAuthenticated Whether the caller proved an identity to get here: an Initial
     *        Access Token when registering, or a Registration Access Token when updating. Only then are
     *        the destination checks run, since each one costs a DNS lookup that no HTTP timeout bounds.
     *        Defaults to false, so a caller that forgets to say loses a diagnostic rather than opening a
     *        way to make this OP resolve names on demand.
     * @return array
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function validate(array $metadata, bool $isCallerAuthenticated = false): array
    {
        $redirectUris = $this->validateRedirectUris($metadata);
        $this->validateInformationalUris($metadata);
        $this->validateRequestUris($metadata);
        $this->validateFetchedUriDestinations($metadata, $isCallerAuthenticated);
        $this->validateContacts($metadata);
        $this->validateApplicationType($metadata);
        $this->validateRedirectUrisForApplicationType($metadata, $redirectUris);
        $this->validateRegisterableProtocolValues($metadata);
        $this->validateSubjectType($metadata);
        $this->rejectUnsupportedFeatures($metadata);
        $this->validateAdditionalMetadata($metadata);

        if ($this->moduleConfig->getDcrImpersonationProtectionEnabled()) {
            $this->enforceImpersonationProtection($metadata, $redirectUris);
        }

        return $metadata;
    }

    /**
     * redirect_uris is REQUIRED; it must be a non-empty array of valid absolute URIs.
     *
     * @param array $metadata
     * @return string[] the validated redirect URIs
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    private function validateRedirectUris(array $metadata): array
    {
        $redirectUris = $metadata[ClaimsEnum::RedirectUris->value] ?? null;

        if (!is_array($redirectUris) || $redirectUris === []) {
            throw OidcServerException::invalidRedirectUri('redirect_uris is required and must be a non-empty array.');
        }

        $validated = [];
        /** @var mixed $redirectUri */
        foreach ($redirectUris as $redirectUri) {
            // Lenient: a redirect URI must be an absolute URI (have a scheme), but we intentionally do not require
            // an http(s) host, so native/custom-scheme and loopback redirect URIs remain valid.
            if (!is_string($redirectUri) || !$this->hasScheme($redirectUri)) {
                throw OidcServerException::invalidRedirectUri('One or more redirect_uris values are invalid.');
            }
            // OIDC Core 3.1.2.1: the redirect_uri MUST NOT include a fragment component.
            if ($this->hasFragment($redirectUri)) {
                throw OidcServerException::invalidRedirectUri('A redirect_uri must not contain a fragment component.');
            }
            $validated[] = $redirectUri;
        }

        return $validated;
    }

    /**
     * logo_uri, client_uri, policy_uri and tos_uri must be valid absolute URIs when present.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    private function validateInformationalUris(array $metadata): void
    {
        foreach (self::URI_CLAIMS as $claim) {
            if (!array_key_exists($claim, $metadata)) {
                continue;
            }

            /** @var mixed $value */
            $value = $metadata[$claim];
            if (!is_string($value) || !$this->isValidAbsoluteUri($value)) {
                throw OidcServerException::invalidClientMetadata(sprintf('Invalid "%s" value.', $claim));
            }
        }
    }

    /**
     * request_uris, when present, must be an array of absolute https URIs. A fragment component is permitted:
     * OpenID Connect Core 1.0 Section 6.2 allows the request_uri to carry a base64url-encoded SHA-256 hash of the
     * referenced Request Object as its fragment.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    private function validateRequestUris(array $metadata): void
    {
        if (!array_key_exists(ClaimsEnum::RequestUris->value, $metadata)) {
            return;
        }

        /** @var mixed $requestUris */
        $requestUris = $metadata[ClaimsEnum::RequestUris->value];
        if (!is_array($requestUris)) {
            throw OidcServerException::invalidClientMetadata('request_uris must be an array.');
        }

        // Bounded before the destination check below resolves any of them, since that is where an
        // over-long list turns into work this OP performs on the caller's behalf.
        if (count($requestUris) > self::MAX_REQUEST_URIS) {
            throw OidcServerException::invalidClientMetadata(
                sprintf('request_uris must not contain more than %d values.', self::MAX_REQUEST_URIS),
            );
        }

        /** @var mixed $requestUri */
        foreach ($requestUris as $requestUri) {
            $scheme = is_string($requestUri) ? parse_url($requestUri, PHP_URL_SCHEME) : null;
            if (
                !is_string($requestUri) ||
                !is_string($scheme) ||
                strtolower($scheme) !== 'https' ||
                $this->extractHost($requestUri) === null
            ) {
                throw OidcServerException::invalidClientMetadata(
                    'Each request_uris value must be a valid https URI.',
                );
            }
        }
    }

    /**
     * Every URI this OP will later fetch from must name a destination the outbound policy permits.
     *
     * Checked here rather than only at fetch time because a refusal at fetch time is not reportable: a
     * `jwks_uri` that resolves inward makes JwksFetcher log and return null, which surfaces later as an
     * unexplained signature failure rather than as the registration problem it is. Refusing the
     * registration turns it into `invalid_client_metadata`, which names the offending value.
     *
     * Note this is a check at a point in time, not a promise: a host permitted now can be repointed at an
     * internal address later, which is what the fetch-time guard and address pinning are for. That guard is
     * where the protection actually lives; this only turns a bad destination into a clear error.
     *
     * Which is why it is skipped for an unauthenticated caller. Each destination costs a synchronous DNS
     * lookup, and the resolver is bounded by nothing the HTTP client configures, so with registration open
     * this loop would be a way for anyone to make the OP wait on names of their choosing. Registration
     * stays protected either way; what an open deployment loses is the clear message, not the refusal.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    private function validateFetchedUriDestinations(array $metadata, bool $isCallerAuthenticated): void
    {
        if (!$isCallerAuthenticated) {
            return;
        }

        $claims = self::FETCHED_URI_CLAIMS;

        // request_uris is a list rather than a single value, so it is flattened in here instead of being
        // walked separately; its shape has already been validated above.
        /** @var mixed $requestUris */
        $requestUris = $metadata[ClaimsEnum::RequestUris->value] ?? [];

        /** @var list<array{string,mixed}> $candidates */
        $candidates = [];
        foreach ($claims as $claim) {
            if (array_key_exists($claim, $metadata)) {
                /** @psalm-suppress MixedAssignment */
                $candidates[] = [$claim, $metadata[$claim]];
            }
        }
        if (is_array($requestUris)) {
            /** @var mixed $requestUri */
            foreach ($requestUris as $requestUri) {
                $candidates[] = [ClaimsEnum::RequestUris->value, $requestUri];
            }
        }

        $checked = [];

        foreach ($candidates as [$claim, $value]) {
            // A value that is not a string, or is empty, is either already rejected by the shape checks
            // above or is not a destination at all; either way it is not this method's to report on.
            if (!is_string($value) || $value === '') {
                continue;
            }

            // Keyed by origin rather than by whole URI, because what costs a DNS lookup is the host. Twenty
            // Request Object paths on one host are one destination, and are charged as one. The scheme and
            // port stay in the key: they are part of what is being permitted, and checking them is free.
            //
            // A URI carrying credentials is exempt from that, since the policy refuses those on the URI
            // itself rather than on where it points, and refuses them before looking anything up. Folding
            // one in behind a clean URI on the same host would let it through unexamined at no saving.
            $origin = $this->extractOrigin($value);
            if (!$this->hasUriCredentials($value)) {
                if (array_key_exists($origin, $checked)) {
                    continue;
                }
                $checked[$origin] = true;
            }

            if ($this->destinationPolicy->isUriAllowed($value)) {
                continue;
            }

            throw OidcServerException::invalidClientMetadata(
                sprintf(
                    'The "%s" value %s names a destination this provider is not permitted to fetch from.',
                    $claim,
                    $value,
                ),
            );
        }
    }

    /**
     * Whether a URI carries a userinfo component, which the destination policy refuses outright.
     *
     * Kept separate from the origin, so that such a URI is never deduplicated against a clean one sharing
     * its host. Answering this costs no lookup.
     */
    private function hasUriCredentials(string $uri): bool
    {
        $parts = parse_url($uri);

        return is_array($parts) && (isset($parts['user']) || isset($parts['pass']));
    }

    /**
     * The part of a URI that decides where a request goes, used to charge one DNS lookup per destination
     * rather than one per URI.
     *
     * A URI that cannot be parsed is keyed by itself, so an unparseable value is still checked rather than
     * being folded together with another one.
     */
    private function extractOrigin(string $uri): string
    {
        $parts = parse_url($uri);

        if (!is_array($parts) || !isset($parts['host'])) {
            return $uri;
        }

        return strtolower($parts['scheme'] ?? '') . '://' .
        strtolower($parts['host']) .
        (isset($parts['port']) ? ':' . $parts['port'] : '');
    }

    /**
     * contacts, when present, must be an array of non-empty strings.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    private function validateContacts(array $metadata): void
    {
        if (!array_key_exists(ClaimsEnum::Contacts->value, $metadata)) {
            return;
        }

        /** @var mixed $contacts */
        $contacts = $metadata[ClaimsEnum::Contacts->value];
        if (!is_array($contacts)) {
            throw OidcServerException::invalidClientMetadata('contacts must be an array.');
        }

        /** @var mixed $contact */
        foreach ($contacts as $contact) {
            if (!is_string($contact) || $contact === '') {
                throw OidcServerException::invalidClientMetadata('contacts must be an array of non-empty strings.');
            }
        }
    }

    /**
     * application_type, when present, must be one of the defined values (web or native).
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    private function validateApplicationType(array $metadata): void
    {
        if (!array_key_exists(ClaimsEnum::ApplicationType->value, $metadata)) {
            return;
        }

        /** @var mixed $applicationType */
        $applicationType = $metadata[ClaimsEnum::ApplicationType->value];
        if (
            !is_string($applicationType) ||
            ApplicationTypesEnum::tryFrom($applicationType) === null
        ) {
            throw OidcServerException::invalidClientMetadata('Invalid application_type value.');
        }
    }

    /**
     * Reject registration of grant_types / response_types / token_endpoint_auth_method values that this OP does not
     * support (the same sets it advertises in discovery via ModuleConfig). Without this, a client could
     * register values that can never be honored and would fail at authentication/token time.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    private function validateRegisterableProtocolValues(array $metadata): void
    {
        $this->rejectUnsupportedArrayValues(
            $metadata,
            ClaimsEnum::GrantTypes->value,
            $this->moduleConfig->getSupportedGrantTypes(),
        );
        $this->rejectUnsupportedArrayValues(
            $metadata,
            ClaimsEnum::ResponseTypes->value,
            $this->moduleConfig->getSupportedResponseTypes(),
        );

        if (array_key_exists(ClaimsEnum::TokenEndpointAuthMethod->value, $metadata)) {
            /** @var mixed $authMethod */
            $authMethod = $metadata[ClaimsEnum::TokenEndpointAuthMethod->value];
            if (
                !is_string($authMethod) ||
                !in_array($authMethod, $this->moduleConfig->getSupportedTokenEndpointAuthMethods(), true)
            ) {
                throw OidcServerException::invalidClientMetadata(
                    'Unsupported token_endpoint_auth_method. Supported: ' .
                    implode(', ', $this->moduleConfig->getSupportedTokenEndpointAuthMethods()) . '.',
                );
            }
        }
    }

    /**
     * Reject the registration when a list-valued metadata field contains a value outside the supported set. When
     * present, the field must be an array of strings, each of which must be supported.
     *
     * @param string[] $supported
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    private function rejectUnsupportedArrayValues(array $metadata, string $claim, array $supported): void
    {
        if (!array_key_exists($claim, $metadata)) {
            return;
        }

        /** @var mixed $values */
        $values = $metadata[$claim];
        if (!is_array($values)) {
            throw OidcServerException::invalidClientMetadata(sprintf('%s must be an array.', $claim));
        }

        /** @var mixed $value */
        foreach ($values as $value) {
            if (!is_string($value) || !in_array($value, $supported, true)) {
                throw OidcServerException::invalidClientMetadata(sprintf(
                    'Unsupported %s value: %s. Supported: %s.',
                    $claim,
                    is_string($value) ? '"' . $value . '"' : var_export($value, true),
                    implode(', ', $supported),
                ));
            }
        }
    }

    /**
     * Verify that every registered redirect_uri conforms to the constraints implied by application_type, as
     * required by OpenID Connect Dynamic Client Registration 1.0 (Section 2, application_type):
     *
     *  - native clients: only custom URI schemes, or loopback URLs (localhost / 127.0.0.1 / [::1]), are allowed;
     *  - web clients using the implicit grant: redirect_uris must use the https scheme and must not use localhost.
     *
     * application_type defaults to "web" when omitted. The https/localhost rule is, per spec, scoped to web clients
     * that use the implicit grant; code-only web clients are not constrained here.
     *
     * @param string[] $redirectUris already-validated redirect URIs (absolute, no fragment)
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    private function validateRedirectUrisForApplicationType(array $metadata, array $redirectUris): void
    {
        /** @var mixed $applicationType */
        $applicationType = $metadata[ClaimsEnum::ApplicationType->value] ?? ApplicationTypesEnum::Web->value;
        $applicationType = is_string($applicationType) ? $applicationType : ApplicationTypesEnum::Web->value;

        if ($applicationType === ApplicationTypesEnum::Native->value) {
            foreach ($redirectUris as $redirectUri) {
                $scheme = strtolower((string)parse_url($redirectUri, PHP_URL_SCHEME));
                $isHttpScheme = in_array($scheme, ['http', 'https'], true);
                // Only custom schemes, or loopback http(s) URLs, are allowed for native clients.
                if ($isHttpScheme && !$this->isLoopbackHost($this->extractHost($redirectUri))) {
                    throw OidcServerException::invalidRedirectUri(sprintf(
                        'For a native client, each redirect_uri must use a custom scheme or a loopback address '
                        . '(localhost, 127.0.0.1 or [::1]); "%s" is not allowed.',
                        $redirectUri,
                    ));
                }
            }

            return;
        }

        // Web client. The https/localhost rule applies only when the client uses the implicit grant.
        if (!$this->clientUsesImplicitGrant($metadata)) {
            return;
        }

        foreach ($redirectUris as $redirectUri) {
            $scheme = strtolower((string)parse_url($redirectUri, PHP_URL_SCHEME));
            if ($scheme !== 'https' || $this->extractHost($redirectUri) === 'localhost') {
                throw OidcServerException::invalidRedirectUri(sprintf(
                    'For a web client using the implicit grant, each redirect_uri must use the https scheme and '
                    . 'must not use localhost as the host; "%s" is not allowed.',
                    $redirectUri,
                ));
            }
        }
    }

    /**
     * Whether the host is a loopback address per OIDC DCR (localhost, 127.0.0.1 or the IPv6 literal [::1]).
     */
    private function isLoopbackHost(?string $host): bool
    {
        return in_array($host, ['localhost', '127.0.0.1', '[::1]', '::1'], true);
    }

    /**
     * Whether the registration declares use of the implicit grant, via grant_types (`implicit`) or via a
     * response_type that requires it (`id_token`, `id_token token`, and the hybrid combinations). Reuses the shared
     * response_type <-> grant_type correspondence so the notion of "uses implicit" stays in one place.
     */
    private function clientUsesImplicitGrant(array $metadata): bool
    {
        /** @var mixed $rawGrantTypes */
        $rawGrantTypes = $metadata[ClaimsEnum::GrantTypes->value] ?? null;
        $grantTypes = is_array($rawGrantTypes) ?
        array_values(array_filter($rawGrantTypes, 'is_string')) :
        [];
        if (in_array(GrantTypesEnum::Implicit->value, $grantTypes, true)) {
            return true;
        }

        /** @var mixed $rawResponseTypes */
        $rawResponseTypes = $metadata[ClaimsEnum::ResponseTypes->value] ?? null;
        $responseTypes = is_array($rawResponseTypes) ?
        array_values(array_filter($rawResponseTypes, 'is_string')) :
        [];

        return in_array(
            GrantTypesEnum::Implicit->value,
            ResponseTypeGrantTypeCorrespondence::requiredGrantTypes($responseTypes),
            true,
        );
    }

    /**
     * subject_type, when present, must be 'public': this OP only issues public subject identifiers (no pairwise).
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    private function validateSubjectType(array $metadata): void
    {
        if (!array_key_exists(ClaimsEnum::SubjectType->value, $metadata)) {
            return;
        }

        /** @var mixed $subjectType */
        $subjectType = $metadata[ClaimsEnum::SubjectType->value];
        // An empty value is treated as "not specified"; any other non-"public" value is rejected.
        if ($subjectType === '' || $subjectType === null) {
            return;
        }

        if ($subjectType !== 'public') {
            throw OidcServerException::invalidClientMetadata(
                'Unsupported subject_type; only "public" is supported.',
            );
        }
    }

    /**
     * Validate additional supported metadata: the behavioral "default when omitted" fields (default_max_age,
     * require_auth_time, default_acr_values) and the informational fields (initiate_login_uri, software_id,
     * software_version).
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    private function validateAdditionalMetadata(array $metadata): void
    {
        if (array_key_exists(ClaimsEnum::DefaultMaxAge->value, $metadata)) {
            /** @var mixed $defaultMaxAge */
            $defaultMaxAge = $metadata[ClaimsEnum::DefaultMaxAge->value];
            if (
                !(is_int($defaultMaxAge) || is_string($defaultMaxAge)) ||
                filter_var($defaultMaxAge, FILTER_VALIDATE_INT, ['options' => ['min_range' => 0]]) === false
            ) {
                throw OidcServerException::invalidClientMetadata('default_max_age must be a non-negative integer.');
            }
        }

        if (array_key_exists(ClaimsEnum::RequireAuthTime->value, $metadata)) {
            /** @var mixed $requireAuthTime */
            $requireAuthTime = $metadata[ClaimsEnum::RequireAuthTime->value];
            if (!is_bool($requireAuthTime)) {
                throw OidcServerException::invalidClientMetadata('require_auth_time must be a boolean.');
            }
        }

        if (array_key_exists(ClaimsEnum::DefaultAcrValues->value, $metadata)) {
            /** @var mixed $defaultAcrValues */
            $defaultAcrValues = $metadata[ClaimsEnum::DefaultAcrValues->value];
            if (!is_array($defaultAcrValues)) {
                throw OidcServerException::invalidClientMetadata('default_acr_values must be an array.');
            }
            $supportedAcrValues = $this->moduleConfig->getAcrValuesSupported();
            /** @var mixed $acr */
            foreach ($defaultAcrValues as $acr) {
                if (!is_string($acr) || $acr === '') {
                    throw OidcServerException::invalidClientMetadata(
                        'default_acr_values must be an array of non-empty strings.',
                    );
                }
                // Reject ACRs the OP does not support (advertised in discovery as acr_values_supported); requesting
                // an unsupported ACR could never be satisfied at the authorization endpoint.
                if (!in_array($acr, $supportedAcrValues, true)) {
                    throw OidcServerException::invalidClientMetadata(
                        sprintf('default_acr_values contains an unsupported ACR value: "%s".', $acr),
                    );
                }
            }
        }

        // initiate_login_uri must be a valid https URI when present.
        if (array_key_exists(ClaimsEnum::InitiateLoginUri->value, $metadata)) {
            /** @var mixed $initiateLoginUri */
            $initiateLoginUri = $metadata[ClaimsEnum::InitiateLoginUri->value];
            $scheme = is_string($initiateLoginUri) ? parse_url($initiateLoginUri, PHP_URL_SCHEME) : null;
            if (
                !is_string($initiateLoginUri) ||
                !is_string($scheme) ||
                strtolower($scheme) !== 'https' ||
                $this->extractHost($initiateLoginUri) === null
            ) {
                throw OidcServerException::invalidClientMetadata('initiate_login_uri must be a valid https URI.');
            }
        }

        // software_id / software_version, when present, must be non-empty strings.
        foreach ([ClaimsEnum::SoftwareId->value, ClaimsEnum::SoftwareVersion->value] as $claim) {
            if (!array_key_exists($claim, $metadata)) {
                continue;
            }
            /** @var mixed $value */
            $value = $metadata[$claim];
            if (!is_string($value) || $value === '') {
                throw OidcServerException::invalidClientMetadata(sprintf('%s must be a non-empty string.', $claim));
            }
        }
    }

    /**
     * Reject metadata requesting features this OP does not support (see UNSUPPORTED_FEATURE_CLAIMS and front-channel
     * logout), rather than silently ignoring it. This keeps the registration response an honest contract: the OP
     * either honors a value or rejects it, it does not accept-and-diverge.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    private function rejectUnsupportedFeatures(array $metadata): void
    {
        foreach (self::UNSUPPORTED_FEATURE_CLAIMS as $claim => $description) {
            /** @var mixed $value */
            $value = $metadata[$claim] ?? null;
            if (is_string($value) && $value !== '') {
                throw OidcServerException::invalidClientMetadata(sprintf('Unsupported metadata: %s.', $description));
            }
        }

        // front-channel logout session flag is a boolean modifier of the (unsupported) front-channel logout feature.
        /** @var mixed $frontchannelSessionRequired */
        $frontchannelSessionRequired = $metadata[self::CLAIM_FRONTCHANNEL_LOGOUT_SESSION_REQUIRED] ?? null;
        if ($frontchannelSessionRequired === true || $frontchannelSessionRequired === 'true') {
            throw OidcServerException::invalidClientMetadata(
                'Unsupported metadata: frontchannel_logout_session_required (front-channel logout is not supported).',
            );
        }
    }

    /**
     * Impersonation protection (OIDC Dynamic Client Registration 1.0, Section 9.1): each protected informational
     * URI must share a host with one of the registered redirect_uris, to mitigate a rogue client supplying the
     * branding (logo) or links of a legitimate one.
     *
     * @param string[] $redirectUris
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    private function enforceImpersonationProtection(array $metadata, array $redirectUris): void
    {
        $allowedHosts = [];
        foreach ($redirectUris as $redirectUri) {
            $host = $this->extractHost($redirectUri);
            if ($host !== null) {
                $allowedHosts[$host] = true;
            }
        }

        foreach (self::IMPERSONATION_PROTECTED_URI_CLAIMS as $claim) {
            if (!array_key_exists($claim, $metadata)) {
                continue;
            }

            // Format was already validated; value is a valid absolute URI string here.
            $host = $this->extractHost((string)$metadata[$claim]);
            if ($host === null || !array_key_exists($host, $allowedHosts)) {
                throw OidcServerException::invalidClientMetadata(sprintf(
                    'The host of "%s" must match the host of one of the redirect_uris '
                    . '(impersonation protection is enabled).',
                    $claim,
                ));
            }
        }
    }

    private function isValidAbsoluteUri(string $uri): bool
    {
        return filter_var($uri, FILTER_VALIDATE_URL) !== false && $this->extractHost($uri) !== null;
    }

    /**
     * Whether the URI has a (non-empty) scheme component, i.e. is an absolute URI.
     */
    private function hasScheme(string $uri): bool
    {
        $scheme = parse_url($uri, PHP_URL_SCHEME);

        return is_string($scheme) && $scheme !== '';
    }

    /**
     * Whether the URI has a fragment component at all. OpenID Connect Core 3.1.2.1 requires redirect_uris to
     * contain no fragment component, which includes an empty fragment: a trailing '#' (e.g. ".../cb#") is a
     * fragment component even though parse_url() reports it as an empty string. Any literal '#' delimiter therefore
     * counts; a percent-encoded '%23' in the path/query does not (it is not a fragment delimiter).
     */
    private function hasFragment(string $uri): bool
    {
        return str_contains($uri, '#');
    }

    /**
     * Extract the lower-cased host component of a URI, or null if absent.
     */
    private function extractHost(string $uri): ?string
    {
        $host = parse_url($uri, PHP_URL_HOST);

        return is_string($host) && $host !== '' ? strtolower($host) : null;
    }
}
