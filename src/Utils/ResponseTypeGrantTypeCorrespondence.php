<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils;

use SimpleSAML\OpenID\Codebooks\GrantTypesEnum;
use SimpleSAML\OpenID\Codebooks\ResponseTypesEnum;

/**
 * The correspondence between OAuth 2.0 `response_type` values and the `grant_type` values that MUST be included in
 * the client's registered `grant_types`, as defined by OpenID Connect Dynamic Client Registration 1.0 (Section 2,
 * Client Metadata).
 *
 * This is the single source of truth shared by the DCR registration path (ClientEntityFactory), the client admin
 * form (ClientForm) and the admin-form JavaScript (serialized via ClientForm::getResponseTypeGrantTypeMapJson()).
 */
final class ResponseTypeGrantTypeCorrespondence
{
    /**
     * Full OIDC correspondence table (response_type => required grant_types). The OP currently advertises only
     * `code`, `id_token` and `id_token token`, but the hybrid rows are included for spec-completeness so the
     * mapping stays correct if more response types are offered later.
     *
     * @return array<string, string[]>
     */
    public static function map(): array
    {
        return [
            ResponseTypesEnum::Code->value => [GrantTypesEnum::AuthorizationCode->value],
            ResponseTypesEnum::IdToken->value => [GrantTypesEnum::Implicit->value],
            ResponseTypesEnum::IdTokenToken->value => [GrantTypesEnum::Implicit->value],
            'code id_token' => [GrantTypesEnum::AuthorizationCode->value, GrantTypesEnum::Implicit->value],
            'code token' => [GrantTypesEnum::AuthorizationCode->value, GrantTypesEnum::Implicit->value],
            'code id_token token' => [GrantTypesEnum::AuthorizationCode->value, GrantTypesEnum::Implicit->value],
        ];
    }

    /**
     * The unique set of grant types required by the given response types, in stable order.
     *
     * @param string[] $responseTypes
     * @return string[]
     */
    public static function requiredGrantTypes(array $responseTypes): array
    {
        $map = self::map();
        $required = [];

        foreach ($responseTypes as $responseType) {
            foreach ($map[$responseType] ?? [] as $grantType) {
                $required[$grantType] = $grantType;
            }
        }

        return array_values($required);
    }

    /**
     * Merge the grant types required by the given response types into the given grant types, preserving the
     * existing order and appending any missing required ones.
     *
     * @param string[] $grantTypes
     * @param string[] $responseTypes
     * @return string[]
     */
    public static function mergeRequiredGrantTypes(array $grantTypes, array $responseTypes): array
    {
        return array_values(array_unique(array_merge(
            array_values($grantTypes),
            self::requiredGrantTypes($responseTypes),
        )));
    }
}
