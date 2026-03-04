<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Codebooks;

enum FlowTypeEnum: string
{
    case OidcAuthorizationCode = 'oidc_authorization_code';
    case OidcImplicit = 'oidc_implicit';
    case OidcHybrid = 'oidc_hybrid';
    case OidcRefreshToken = 'oidc_refresh_token';

    case VciAuthorizationCode = 'vci_authorization_code';
    case VciPreAuthorizedCode = 'vci_pre_authorized_code';

    public function isOidcFlow(): bool
    {
        return match ($this) {
            self::OidcAuthorizationCode, self::OidcImplicit, self::OidcHybrid => true,
            default => false,
        };
    }

    public function isVciFlow(): bool
    {
        return match ($this) {
            self::VciAuthorizationCode, self::VciPreAuthorizedCode => true,
            default => false,
        };
    }
}
