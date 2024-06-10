<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Codebooks;

enum RoutesEnum: string
{
    case OpenIdAuthorization = 'authorization';
    case OpenIdConfiguration = '.well-known/openid-configuration';
    case OpenIdFederationConfiguration = '.well-known/openid-federation';
    case OpenIdFederationFetch = 'federation/fetch';
    case OpenIdToken = 'token';
    case OpenIdUserInfo = 'userinfo';
}
