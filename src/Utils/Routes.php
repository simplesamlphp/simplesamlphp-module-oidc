<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils;

use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Codebooks\ParametersEnum;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\ModuleConfig;
use Symfony\Component\HttpFoundation\RedirectResponse;

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

    public function getRedirectResponseToModuleUrl(
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

    /*****************************************************************************************************************
     * Admin area
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

    /*****************************************************************************************************************
     * OpenID Connect
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
     * OpenID Federation
     ****************************************************************************************************************/

    public function urlFederationConfiguration(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::FederationConfiguration->value, $parameters);
    }

    public function urlFederationFetch(array $parameters = []): string
    {
        return $this->getModuleUrl(RoutesEnum::FederationFetch->value, $parameters);
    }
}
