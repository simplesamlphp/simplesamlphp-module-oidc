<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\Registration;

use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\OpenID\Codebooks\ApplicationTypesEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;

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

    public function __construct(
        private readonly ModuleConfig $moduleConfig,
    ) {
    }

    /**
     * Validate the incoming registration metadata. Returns the metadata unchanged on success.
     *
     * @param array $metadata
     * @return array
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function validate(array $metadata): array
    {
        $redirectUris = $this->validateRedirectUris($metadata);
        $this->validateInformationalUris($metadata);
        $this->validateContacts($metadata);
        $this->validateApplicationType($metadata);

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
     * Whether the URI has a fragment component (the part after '#').
     */
    private function hasFragment(string $uri): bool
    {
        $fragment = parse_url($uri, PHP_URL_FRAGMENT);

        return is_string($fragment) && $fragment !== '';
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
