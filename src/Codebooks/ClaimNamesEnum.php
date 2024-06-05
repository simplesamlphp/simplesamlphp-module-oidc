<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Codebooks;

enum ClaimNamesEnum: string
{
    case Algorithm = 'alg';
    case AuthorityHints = 'authority_hints';
    case BackChannelLogoutUri = 'backchannel_logout_uri';
    case ClientId = 'client_id';
    case ClientName = 'client_name';
    case ClientRegistrationTypes = 'client_registration_types';
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
    case Scope = 'scope';
    case Subject = 'sub';
    case Type = 'typ';
}
