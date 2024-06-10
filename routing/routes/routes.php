<?php

/**
 * OIDC module routes file.
 */

declare(strict_types=1);

use SimpleSAML\Module\oidc\Codebooks\HttpMethodsEnum;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\Controller\AccessTokenController;
use SimpleSAML\Module\oidc\Controller\AuthorizationController;
use SimpleSAML\Module\oidc\Controller\ConfigurationDiscoveryController;
use SimpleSAML\Module\oidc\Controller\Federation\EntityStatementController;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

/** @psalm-suppress InvalidArgument */
return function (RoutingConfigurator $routes): void {
    $routes->add(RoutesEnum::OpenIdConfiguration->name, RoutesEnum::OpenIdConfiguration->value)
        ->controller(ConfigurationDiscoveryController::class);

    /**
     * OpenID Connect Core protocol routes.
     */
    $routes->add(RoutesEnum::OpenIdAuthorization->name, RoutesEnum::OpenIdAuthorization->value)
        ->controller([AuthorizationController::class, 'authorization']);
    $routes->add(RoutesEnum::OpenIdToken->name, RoutesEnum::OpenIdToken->value)
        ->controller([AccessTokenController::class, 'token']);

    /**
     * OpenID Federation related routes.
     */
    $routes->add(RoutesEnum::OpenIdFederationConfiguration->name, RoutesEnum::OpenIdFederationConfiguration->value)
        ->controller([EntityStatementController::class, 'configuration'])
        ->methods([HttpMethodsEnum::GET->value]);

    $routes->add(RoutesEnum::OpenIdFederationFetch->name, RoutesEnum::OpenIdFederationFetch->value)
        ->controller([EntityStatementController::class, 'fetch'])
        ->methods([HttpMethodsEnum::GET->value]);
};
