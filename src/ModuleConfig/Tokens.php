<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\ModuleConfig;

abstract class Tokens
{
    final public const OPTION_AUTHORIZATION_CODE_TTL = 'authCodeDuration';
    final public const OPTION_REFRESH_TOKEN_TTL = 'refreshTokenDuration';
    final public const OPTION_ACCESS_TOKEN_TTL = 'accessTokenDuration';
    final public const OPTION_SIGNER = 'signer';
}
