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
    case AdminConfigVerifiableCredential = 'admin/config/verifiable-credential';
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
    case AdminTestVerifiableCredentialIssuance = 'admin/test/verifiable-credential-issuance';


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
     * OAuth 2.0 Authorization Server
     ****************************************************************************************************************/

    // OAuth 2.0 Authorization Server Metadata https://www.rfc-editor.org/rfc/rfc8414.html
    case OAuth2Configuration = '.well-known/oauth-authorization-server';

    /*****************************************************************************************************************
     * OpenID Federation
     ****************************************************************************************************************/

    case FederationConfiguration = '.well-known/openid-federation';
    case FederationFetch = 'federation/fetch';
    case FederationList = 'federation/list';

    /*****************************************************************************************************************
     * OpenID for Verifiable Credential Issuance
     ****************************************************************************************************************/

    case CredentialIssuerConfiguration = '.well-known/openid-credential-issuer';
    case CredentialIssuerCredential = 'credential-issuer/credential';

    /*****************************************************************************************************************
     * SD-JWT-based Verifiable Credentials (SD-JWT VC)
     ****************************************************************************************************************/

    case JwtVcIssuerConfiguration = '.well-known/jwt-vc-issuer';

    /*****************************************************************************************************************
     * API
     ****************************************************************************************************************/

    case ApiVciPreAuthorizedCredentialOffer = 'api/vci/pre-authorized-credential-offer';
}
