<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Codebooks;

enum RoutesEnum: string
{
    /*****************************************************************************************************************
     * Admin area
     ****************************************************************************************************************/

    case AdminConfigGeneral = 'admin/config/general';
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

    // Credential status management

    case AdminCredentialStatus = 'admin/credential-status';
    case AdminCredentialStatusChange = 'admin/credential-status/change';

    // Testing
    case AdminTestTrustChainResolution = 'admin/test/trust-chain-resolution';
    case AdminTestTrustMarkValidation = 'admin/test/trust-mark-validation';
    case AdminTestFederationDiscovery = 'admin/test/federation-discovery';
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
    // OpenID Connect Dynamic Client Registration endpoint (create + read).
    case Registration = 'register';

    /*****************************************************************************************************************
     * OAuth 2.0 Authorization Server
     ****************************************************************************************************************/

    // OAuth 2.0 Authorization Server Metadata https://www.rfc-editor.org/rfc/rfc8414.html
    case OAuth2Configuration = '.well-known/oauth-authorization-server';
    case PushedAuthorizationRequest = 'par';

    /*****************************************************************************************************************
     * OpenID Federation
     ****************************************************************************************************************/

    // Only the entity configuration endpoint is served. As a leaf entity, this OP must not expose fetch or
    // subordinate listing endpoints, so no routes for those exist (nor should they be added).
    case FederationConfiguration = '.well-known/openid-federation';

    /*****************************************************************************************************************
     * OpenID for Verifiable Credential Issuance
     ****************************************************************************************************************/

    case CredentialIssuerConfiguration = '.well-known/openid-credential-issuer';
    case CredentialIssuerCredential = 'credential-issuer/credential';
    case CredentialIssuerNonce = 'credential-issuer/nonce';
    case CredentialJsonLdContext = 'credential-issuer/context/{credentialConfigurationId}';

    /*****************************************************************************************************************
     * Token Status List
     ****************************************************************************************************************/

    // Publishes one Status List Token. Deliberately not gated on the Verifiable Credential Issuance
    // switch: credentials which were already issued point at these URIs and have to stay verifiable,
    // so turning issuance off must not make them unresolvable.
    case StatusList = 'statuslist/{statusListId}';

    /*****************************************************************************************************************
     * SD-JWT-based Verifiable Credentials (SD-JWT VC)
     ****************************************************************************************************************/

    case JwtVcIssuerConfiguration = '.well-known/jwt-vc-issuer';

    /*****************************************************************************************************************
     * Decentralized Identifiers
     ****************************************************************************************************************/

    // Publishes the DID document for the configured did:web identifier. The did:web method appends
    // "did.json" to the path its identifier transforms to, so the name of this route is fixed by the
    // method rather than chosen here. Like the Status List route, it is deliberately not gated on the
    // Verifiable Credential Issuance switch: a credential issued under a did:web identity can only be
    // verified by resolving that DID, so withholding this document makes such credentials unverifiable
    // rather than merely unissuable.
    case VciDidDocument = 'did.json';

    /*****************************************************************************************************************
     * API
     ****************************************************************************************************************/

    case ApiVciCredentialOffer = 'api/vci/credential-offer';
    case ApiVciCredentialStatus = 'api/vci/credential-status';
    case ApiOAuth2TokenIntrospection = 'api/oauth2/token-introspection';
}
