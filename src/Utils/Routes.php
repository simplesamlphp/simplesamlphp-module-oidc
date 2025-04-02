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
        mixed $data = null,
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

    // Testing

    public function urlAdminTestTrustChainResolution(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::AdminTestTrustChainResolution->value, $parameters);
    }

    public function urlAdminTestTrustMarkValidation(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::AdminTestTrustMarkValidation->value, $parameters);
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

    /*****************************************************************************************************************
     * OpenID Federation URLs.
     ****************************************************************************************************************/

    public function urlFederationConfiguration(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::FederationConfiguration->value, $parameters);
    }

    public function urlFederationFetch(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::FederationFetch->value, $parameters);
    }

    public function urlFederationList(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::FederationList->value, $parameters);
    }
}
