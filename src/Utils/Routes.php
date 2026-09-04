<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils;

use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Codebooks\ParametersEnum;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\ModuleConfig;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;

class Routes
{
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly SspBridge $sspBridge,
    ) {
    }


    public function getModuleUrl(string $resource = '', array $parameters = []): string
    {
        $resource = $this->moduleConfig->moduleName() . '/' . $resource;

        return $this->sspBridge->module()->getModuleUrl($resource, $parameters);
    }

    /*****************************************************************************************************************
     * Response factory methods.
     ****************************************************************************************************************/

    public function newRedirectResponseToModuleUrl(
        string $resource = '',
        array $parameters = [],
        int $status = 302,
        array $headers = [],
    ): RedirectResponse {
        return new RedirectResponse(
            $this->getModuleUrl($resource, $parameters),
            $status,
            $headers,
        );
    }


    public function newResponse(
        ?string $content = '',
        int $status = 200,
        array $headers = [],
    ): Response {
        return new Response($content, $status, $headers);
    }


    public function newJsonResponse(
        array|null $data = null,
        int $status = 200,
        array $headers = [],
        bool $json = false,
    ): JsonResponse {
        return new JsonResponse($data, $status, $headers, $json);
    }


    public function newJsonErrorResponse(
        string $error,
        string $description,
        int $httpCode = 500,
        array $headers = [],
    ): JsonResponse {
        return $this->newJsonResponse(
            ['error' => $error, 'error_description' => $description],
            $httpCode,
            $headers,
        );
    }

    /*****************************************************************************************************************
     * Admin area URLs.
     ****************************************************************************************************************/

    public function urlAdminConfigGeneral(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::AdminConfigGeneral->value, $parameters);
    }


    public function urlAdminConfigProtocol(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::AdminConfigProtocol->value, $parameters);
    }


    public function urlAdminConfigFederation(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::AdminConfigFederation->value, $parameters);
    }


    public function urlAdminMigrations(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::AdminMigrations->value, $parameters);
    }


    public function urlAdminMigrationsRun(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::AdminMigrationsRun->value, $parameters);
    }

    // Client management

    public function urlAdminClients(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::AdminClients->value, $parameters);
    }


    public function urlAdminClientsShow(string $clientId, array $parameters = []): string
    {
        $parameters[ParametersEnum::ClientId->value] = $clientId;
        return $this->getModuleUrl(RoutesEnum::AdminClientsShow->value, $parameters);
    }


    public function urlAdminClientsEdit(string $clientId, array $parameters = []): string
    {
        $parameters[ParametersEnum::ClientId->value] = $clientId;
        return $this->getModuleUrl(RoutesEnum::AdminClientsEdit->value, $parameters);
    }


    public function urlAdminClientsAdd(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::AdminClientsAdd->value, $parameters);
    }


    public function urlAdminClientsResetSecret(string $clientId, array $parameters = []): string
    {
        $parameters[ParametersEnum::ClientId->value] = $clientId;
        return $this->getModuleUrl(RoutesEnum::AdminClientsResetSecret->value, $parameters);
    }


    public function urlAdminClientsDelete(string $clientId, array $parameters = []): string
    {
        $parameters[ParametersEnum::ClientId->value] = $clientId;
        return $this->getModuleUrl(RoutesEnum::AdminClientsDelete->value, $parameters);
    }

    // Credential status management

    public function urlAdminCredentialStatus(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::AdminCredentialStatus->value, $parameters);
    }


    public function urlAdminCredentialStatusChange(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::AdminCredentialStatusChange->value, $parameters);
    }

    // Testing

    public function urlAdminTestTrustChainResolution(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::AdminTestTrustChainResolution->value, $parameters);
    }


    public function urlAdminTestTrustMarkValidation(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::AdminTestTrustMarkValidation->value, $parameters);
    }


    public function urlAdminTestFederationDiscovery(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::AdminTestFederationDiscovery->value, $parameters);
    }


    public function urlAdminTestVerifiableCredentialIssuance(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::AdminTestVerifiableCredentialIssuance->value, $parameters);
    }

    /*****************************************************************************************************************
     * OAuth 2.0 Authorization Server
     ****************************************************************************************************************/

    public function urlOAuth2Configuration(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::OAuth2Configuration->value, $parameters);
    }

    /*****************************************************************************************************************
     * OpenID Connect URLs.
     ****************************************************************************************************************/

    public function urlConfiguration(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::Configuration->value, $parameters);
    }


    public function urlAuthorization(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::Authorization->value, $parameters);
    }


    public function urlToken(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::Token->value, $parameters);
    }


    public function urlUserInfo(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::UserInfo->value, $parameters);
    }


    public function urlJwks(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::Jwks->value, $parameters);
    }


    public function urlEndSession(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::EndSession->value, $parameters);
    }


    /**
     * Dynamic Client Registration endpoint. Only served (and only advertised in OP metadata) when
     * Dynamic Client Registration is enabled.
     */
    public function urlRegistration(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::Registration->value, $parameters);
    }

    /*****************************************************************************************************************
     * OpenID Federation URLs.
     ****************************************************************************************************************/

    public function urlFederationConfiguration(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::FederationConfiguration->value, $parameters);
    }


    public function urlPushedAuthorizationRequest(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::PushedAuthorizationRequest->value, $parameters);
    }

    /*****************************************************************************************************************
     * OpenID for Verifiable Credential Issuance URLs.
     ****************************************************************************************************************/

    public function urlCredentialIssuerConfiguration(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::CredentialIssuerConfiguration->value, $parameters);
    }


    public function urlCredentialIssuerCredential(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::CredentialIssuerCredential->value, $parameters);
    }


    public function urlCredentialIssuerNonce(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::CredentialIssuerNonce->value, $parameters);
    }


    public function urlCredentialJsonLdContext(string $credentialConfigurationId, array $parameters = []): string
    {
        $path = str_replace(
            '{credentialConfigurationId}',
            rawurlencode($credentialConfigurationId),
            RoutesEnum::CredentialJsonLdContext->value,
        );

        return $this->getModuleUrl($path, $parameters);
    }

    /*****************************************************************************************************************
     * Token Status List URLs.
     ****************************************************************************************************************/

    /**
     * URL of one Status List Token.
     *
     * This is minted once, when the list is created, and stored on it. Referenced Tokens carry that
     * stored string and Status List Tokens repeat it as their `sub`, both verbatim, because a Relying
     * Party rejects a token whose subject is not byte for byte the URI its credential named. Never
     * re-derive it for an existing list: changing the base URL would produce a different string for a
     * list which credentials in the wild already point at.
     */
    public function urlStatusList(string $statusListId, array $parameters = []): string
    {
        $path = str_replace(
            '{statusListId}',
            rawurlencode($statusListId),
            RoutesEnum::StatusList->value,
        );

        return $this->getModuleUrl($path, $parameters);
    }

    /*****************************************************************************************************************
     * SD-JWT-based Verifiable Credentials (SD-JWT VC)
     ****************************************************************************************************************/

    public function urlJwtVcIssuerConfiguration(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::JwtVcIssuerConfiguration->value, $parameters);
    }

    /*****************************************************************************************************************
     * Decentralized Identifiers
     ****************************************************************************************************************/

    public function urlVciDidDocument(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::VciDidDocument->value, $parameters);
    }

    /*****************************************************************************************************************
     * API
     ****************************************************************************************************************/

    public function urlApiVciCredentialOffer(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::ApiVciCredentialOffer->value, $parameters);
    }


    public function urlApiVciCredentialStatus(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::ApiVciCredentialStatus->value, $parameters);
    }


    public function urlApiOAuth2TokenIntrospection(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::ApiOAuth2TokenIntrospection->value, $parameters);
    }
}
