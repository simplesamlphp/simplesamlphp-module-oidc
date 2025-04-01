<?php

/**
 * OIDC module routes file.
 */

declare(strict_types=1);

use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\Controllers\AccessTokenController;
use SimpleSAML\Module\oidc\Controllers\Admin\ClientController;
use SimpleSAML\Module\oidc\Controllers\Admin\ConfigController;
use SimpleSAML\Module\oidc\Controllers\Admin\TestController;
use SimpleSAML\Module\oidc\Controllers\AuthorizationController;
use SimpleSAML\Module\oidc\Controllers\ConfigurationDiscoveryController;
use SimpleSAML\Module\oidc\Controllers\EndSessionController;
use SimpleSAML\Module\oidc\Controllers\Federation\EntityStatementController;
use SimpleSAML\Module\oidc\Controllers\Federation\SubordinateListingsController;
use SimpleSAML\Module\oidc\Controllers\JwksController;
use SimpleSAML\Module\oidc\Controllers\UserInfoController;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

/** @psalm-suppress InvalidArgument */
return function (RoutingConfigurator $routes): void {

    /*****************************************************************************************************************
     * Admin area
     ****************************************************************************************************************/

    $routes->add(RoutesEnum::AdminMigrations->name, RoutesEnum::AdminMigrations->value)
        ->controller([ConfigController::class, 'migrations'])
        ->methods([HttpMethodsEnum::GET->value]);
    $routes->add(RoutesEnum::AdminMigrationsRun->name, RoutesEnum::AdminMigrationsRun->value)
        ->controller([ConfigController::class, 'runMigrations'])
        ->methods([HttpMethodsEnum::POST->value]);
    $routes->add(RoutesEnum::AdminConfigProtocol->name, RoutesEnum::AdminConfigProtocol->value)
        ->controller([ConfigController::class, 'protocolSettings']);
    $routes->add(RoutesEnum::AdminConfigFederation->name, RoutesEnum::AdminConfigFederation->value)
        ->controller([ConfigController::class, 'federationSettings']);

    // Client management

    $routes->add(RoutesEnum::AdminClients->name, RoutesEnum::AdminClients->value)
        ->controller([ClientController::class, 'index']);
    $routes->add(RoutesEnum::AdminClientsAdd->name, RoutesEnum::AdminClientsAdd->value)
        ->controller([ClientController::class, 'add'])
        ->methods([HttpMethodsEnum::GET->value, HttpMethodsEnum::POST->value]);
    $routes->add(RoutesEnum::AdminClientsShow->name, RoutesEnum::AdminClientsShow->value)
        ->controller([ClientController::class, 'show'])
        ->methods([HttpMethodsEnum::GET->value]);
    $routes->add(RoutesEnum::AdminClientsEdit->name, RoutesEnum::AdminClientsEdit->value)
        ->controller([ClientController::class, 'edit'])
        ->methods([HttpMethodsEnum::GET->value, HttpMethodsEnum::POST->value]);
    $routes->add(RoutesEnum::AdminClientsResetSecret->name, RoutesEnum::AdminClientsResetSecret->value)
        ->controller([ClientController::class, 'resetSecret'])
        ->methods([HttpMethodsEnum::POST->value]);
    $routes->add(RoutesEnum::AdminClientsDelete->name, RoutesEnum::AdminClientsDelete->value)
        ->controller([ClientController::class, 'delete'])
        ->methods([HttpMethodsEnum::POST->value]);

    // Testing

    $routes->add(RoutesEnum::AdminTestTrustChainResolution->name, RoutesEnum::AdminTestTrustChainResolution->value)
        ->controller([TestController::class, 'trustChainResolution'])
        ->methods([HttpMethodsEnum::GET->value, HttpMethodsEnum::POST->value]);
    $routes->add(RoutesEnum::AdminTestTrustMarkValidation->name, RoutesEnum::AdminTestTrustMarkValidation->value)
        ->controller([TestController::class, 'trustMarkValidation'])
        ->methods([HttpMethodsEnum::GET->value, HttpMethodsEnum::POST->value]);

    /*****************************************************************************************************************
     * OpenID Connect
     ****************************************************************************************************************/

    $routes->add(RoutesEnum::Configuration->name, RoutesEnum::Configuration->value)
        ->controller(ConfigurationDiscoveryController::class);

    $routes->add(RoutesEnum::Authorization->name, RoutesEnum::Authorization->value)
        ->controller([AuthorizationController::class, 'authorization']);
    $routes->add(RoutesEnum::Token->name, RoutesEnum::Token->value)
        ->controller([AccessTokenController::class, 'token']);
    $routes->add(RoutesEnum::UserInfo->name, RoutesEnum::UserInfo->value)
        ->controller([UserInfoController::class, 'userInfo']);
    $routes->add(RoutesEnum::EndSession->name, RoutesEnum::EndSession->value)
        ->controller([EndSessionController::class, 'endSession']);
    $routes->add(RoutesEnum::Jwks->name, RoutesEnum::Jwks->value)
        ->controller([JwksController::class, 'jwks']);

    /*****************************************************************************************************************
     * OpenID Federation
     ****************************************************************************************************************/

    $routes->add(RoutesEnum::FederationConfiguration->name, RoutesEnum::FederationConfiguration->value)
        ->controller([EntityStatementController::class, 'configuration'])
        ->methods([HttpMethodsEnum::GET->value]);

    $routes->add(RoutesEnum::FederationFetch->name, RoutesEnum::FederationFetch->value)
        ->controller([EntityStatementController::class, 'fetch'])
        ->methods([HttpMethodsEnum::GET->value]);

    $routes->add(RoutesEnum::FederationList->name, RoutesEnum::FederationList->value)
        ->controller([SubordinateListingsController::class, 'list'])
        ->methods([HttpMethodsEnum::GET->value]);
};
