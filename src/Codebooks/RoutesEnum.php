<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Codebooks;

enum RoutesEnum: string
{
    /*****************************************************************************************************************
     * Admin area
     ****************************************************************************************************************/

    case AdminConfigProtocol = 'admin/config/protocol';
    case AdminConfigFederation = 'admin/config/federation';
    case AdminMigrations = 'admin/migrations';
    case AdminMigrationsRun = 'admin/migrations/run';

    // Client management

    case AdminClients = 'admin/clients';
    case AdminClientsShow = 'admin/clients/show';
    case AdminClientsEdit = 'admin/clients/edit';
    case AdminClientsAdd = 'admin/clients/add';
    case AdminClientsResetSecret = 'admin/clients/reset-secret';
    case AdminClientsDelete = 'admin/clients/delete';

    // Testing
    case AdminTestTrustChainResolution = 'admin/test/trust-chain-resolution';
    case AdminTestTrustMarkValidation = 'admin/test/trust-mark-validation';


    /*****************************************************************************************************************
     * OpenID Connect
     ****************************************************************************************************************/

    case Configuration = '.well-known/openid-configuration';
    case Authorization = 'authorization';
    case Token = 'token';
    case UserInfo = 'userinfo';
    case Jwks = 'jwks';
    case EndSession = 'end-session';

    /*****************************************************************************************************************
     * OpenID Federation
     ****************************************************************************************************************/

    case FederationConfiguration = '.well-known/openid-federation';
    case FederationFetch = 'federation/fetch';
    case FederationList = 'federation/list';
}
