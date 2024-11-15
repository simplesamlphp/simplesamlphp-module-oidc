<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils;

use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\ModuleConfig;

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
        return $this->getModuleUrl(RoutesEnum::AdminMigrationsRun->value, $parameters);
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
