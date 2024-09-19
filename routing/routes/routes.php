<?php

/**
 * OIDC module routes file.
 */

declare(strict_types=1);

use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\Controller\AccessTokenController;
use SimpleSAML\Module\oidc\Controller\AuthorizationController;
use SimpleSAML\Module\oidc\Controller\ConfigurationDiscoveryController;
use SimpleSAML\Module\oidc\Controller\EndSessionController;
use SimpleSAML\Module\oidc\Controller\Federation\EntityStatementController;
use SimpleSAML\Module\oidc\Controller\JwksController;
use SimpleSAML\Module\oidc\Controller\UserInfoController;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

/** @psalm-suppress InvalidArgument */
return function (RoutingConfigurator $routes): void {
    $routes->add(RoutesEnum::Configuration->name, RoutesEnum::Configuration->value)
        ->controller(ConfigurationDiscoveryController::class);

    /**
     * OpenID Connect Core protocol routes.
     */
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

    /**
     * OpenID Federation related routes.
     */
    $routes->add(RoutesEnum::FederationConfiguration->name, RoutesEnum::FederationConfiguration->value)
        ->controller([EntityStatementController::class, 'configuration'])
        ->methods([HttpMethodsEnum::GET->value]);

    $routes->add(RoutesEnum::FederationFetch->name, RoutesEnum::FederationFetch->value)
        ->controller([EntityStatementController::class, 'fetch'])
        ->methods([HttpMethodsEnum::GET->value]);

    // TODO mivanci delete
    $routes->add('test', 'test')
        ->controller(\SimpleSAML\Module\oidc\Controller\Federation\Test::class);
};
