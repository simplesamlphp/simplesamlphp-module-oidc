<?php

declare(strict_types=1);

use SimpleSAML\Module\oidc\Codebooks\HttpMethodsEnum;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\Controller\ConfigurationDiscoveryController;
use SimpleSAML\Module\oidc\Controller\Federation\EntityStatementController;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

/** @psalm-suppress InvalidArgument */
return function (RoutingConfigurator $routes): void {
    $routes->add(RoutesEnum::OpenIdConfiguration->name, RoutesEnum::OpenIdConfiguration->value)
        ->controller(ConfigurationDiscoveryController::class);

    $routes->add(RoutesEnum::OpenIdFederationConfiguration->name, RoutesEnum::OpenIdFederationConfiguration->value)
        ->controller([EntityStatementController::class, 'configuration'])
        ->methods([HttpMethodsEnum::GET->value]);

    $routes->add(RoutesEnum::OpenIdFederationFetch->name, RoutesEnum::OpenIdFederationFetch->value)
        ->controller([EntityStatementController::class, 'fetch'])
        ->methods([HttpMethodsEnum::GET->value]);
};
