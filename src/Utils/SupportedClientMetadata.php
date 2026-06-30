<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils;

use SimpleSAML\OpenID\Codebooks\GrantTypesEnum;
use SimpleSAML\OpenID\Codebooks\ResponseTypesEnum;
use SimpleSAML\OpenID\Codebooks\TokenEndpointAuthMethodsEnum;

/**
 * Single source of truth for the OAuth 2.0 / OpenID Connect values a client may be registered to use:
 * `response_types`, `grant_types` and `token_endpoint_auth_method`.
 *
 * Shared by the OP discovery metadata (OpMetadataService), the dynamic client registration validator
 * (ClientMetadataValidator) and the client admin form (ClientForm), so the advertised, the accepted and the
 * admin-selectable sets cannot drift apart.
 *
 * Note: this is the per-client *registerable* set. The discovery `grant_types_supported` may advertise additional
 * grant types that are not registered per client (e.g. the VCI pre-authorized_code grant); that extension is applied
 * by OpMetadataService on top of these values.
 */
final class SupportedClientMetadata
{
    /**
     * @return string[]
     */
    public static function responseTypes(): array
    {
        return [
            ResponseTypesEnum::Code->value,
            ResponseTypesEnum::IdToken->value,
            ResponseTypesEnum::IdTokenToken->value,
        ];
    }

    /**
     * @return string[]
     */
    public static function grantTypes(): array
    {
        return [
            GrantTypesEnum::AuthorizationCode->value,
            GrantTypesEnum::Implicit->value,
            GrantTypesEnum::RefreshToken->value,
        ];
    }

    /**
     * @return string[]
     */
    public static function tokenEndpointAuthMethods(): array
    {
        return [
            TokenEndpointAuthMethodsEnum::ClientSecretBasic->value,
            TokenEndpointAuthMethodsEnum::ClientSecretPost->value,
            TokenEndpointAuthMethodsEnum::PrivateKeyJwt->value,
            TokenEndpointAuthMethodsEnum::None->value,
        ];
    }
}
