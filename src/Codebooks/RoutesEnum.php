<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Codebooks;

enum RoutesEnum: string
{
    // Admin area
    case AdminConfigOverview = 'admin/config-overview';

    // Protocols
    case Authorization = 'authorization';
    case Configuration = '.well-known/openid-configuration';
    case FederationConfiguration = '.well-known/openid-federation';
    case FederationFetch = 'federation/fetch';
    case Jwks = 'jwks';
    case Token = 'token';
    case UserInfo = 'userinfo';
    case EndSession = 'end-session';
}
