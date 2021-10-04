<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * Copyright (C) 2018 by the Spanish Research and Academic Network.
 *
 * This code was developed by Universidad de Córdoba (UCO https://www.uco.es)
 * for the RedIRIS SIR service (SIR: http://www.rediris.es/sir)
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\SimpleSAML\Module\oidc\Controller;

use Laminas\Diactoros\Response\JsonResponse;
use Laminas\Diactoros\ServerRequest;
use PhpSpec\ObjectBehavior;
use SimpleSAML\Module\oidc\Controller\OpenIdConnectDiscoverConfigurationController;
use SimpleSAML\Module\oidc\Services\OidcOpenIdProviderMetadataService;

class OpenIdConnectDiscoverConfigurationControllerSpec extends ObjectBehavior
{
    public const OIDC_OP_METADATA = [
        'issuer' => 'http://localhost',
        'authorization_endpoint' => 'http://localhost/authorize.php',
        'token_endpoint' => 'http://localhost/token.php',
        'userinfo_endpoint' => 'http://localhost/userinfo.php',
        'jwks_uri' => 'http://localhost/jwks.php',
        'scopes_supported' => ['openid'],
        'response_types_supported' => ['code', 'token', 'id_token', 'id_token token'],
        'subject_types_supported' => ['public'],
        'id_token_signing_alg_values_supported' => ['RS256'],
        'code_challenge_methods_supported' => ['plain', 'S256'],
        'end_session_endpoint' => 'http://localhost/logout.php',
    ];

    /**
     * @param OidcOpenIdProviderMetadataService $oidcOpenIdProviderMetadataService
     * @return void
     */
    public function let(
        OidcOpenIdProviderMetadataService $oidcOpenIdProviderMetadataService
    ): void {
        $oidcOpenIdProviderMetadataService->getMetadata()->willReturn(self::OIDC_OP_METADATA);

        $this->beConstructedWith($oidcOpenIdProviderMetadataService);
    }

    /**
     * @return void
     */
    public function it_is_initializable()
    {
        $this->shouldHaveType(OpenIdConnectDiscoverConfigurationController::class);
    }

    /**
     * @param ServerRequest $request
     * @return void
     */
    public function it_returns_openid_connect_configuration(
        ServerRequest $request
    ): void {
        $this->__invoke($request)->shouldHavePayload(self::OIDC_OP_METADATA);
    }

    public function getMatchers(): array
    {
        return [
            'havePayload' => function (JsonResponse $subject, $payload) {
                return $payload === $subject->getPayload();
            },
        ];
    }
}
