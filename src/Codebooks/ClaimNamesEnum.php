<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Codebooks;

// TODO mivanci Merge this with openid library.
enum ClaimNamesEnum: string
{
    case Algorithm = 'alg';
    case AuthorityHints = 'authority_hints';
    case AuthorizationEndpoint = 'authorization_endpoint';
    case BackChannelLogoutUri = 'backchannel_logout_uri';
    case ClientId = 'client_id';
    case ClientName = 'client_name';
    case ClientRegistrationTypes = 'client_registration_types';
    case ClientRegistrationTypesSupported = 'client_registration_types_supported';
    case Contacts = 'contacts';
    case ExpirationTime = 'exp';
    case FederationFetchEndpoint = 'federation_fetch_endpoint';
    case HomepageUri = 'homepage_uri';
    case Issuer = 'iss';
    case JsonWebKeySet = 'jwks';
    case KeyId = 'kid';
    case LogoUri = 'logo_uri';
    case Metadata = 'metadata';
    case OrganizationName = 'organization_name';
    case PolicyUri = 'policy_uri';
    case PostLogoutRedirectUris = 'post_logout_redirect_uris';
    case PublicKeyUse = 'use';
    case RedirectUris = 'redirect_uris';
    case RequestAuthenticationMethodsSupported = 'request_authentication_methods_supported';
    case RequestAuthenticationSigningAlgValuesSupported = 'request_authentication_signing_alg_values_supported';
    case Scope = 'scope';
    case Subject = 'sub';
    case Type = 'typ';
}
