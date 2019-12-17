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

namespace spec\SimpleSAML\Modules\OpenIDConnect\Controller;

use PhpSpec\ObjectBehavior;
use SimpleSAML\Configuration;
use SimpleSAML\Modules\OpenIDConnect\Controller\OpenIdConnectDiscoverConfigurationController;
use SimpleSAML\Modules\OpenIDConnect\Services\ConfigurationService;
use Zend\Diactoros\Response\JsonResponse;
use Zend\Diactoros\ServerRequest;

class OpenIdConnectDiscoverConfigurationControllerSpec extends ObjectBehavior
{
    /**
     * @param \SimpleSAML\Modules\OpenIDConnect\Services\ConfigurationService $configurationService
     * @return void
     */
    public function let(
        ConfigurationService $configurationService)
    {
        $this->beConstructedWith($configurationService);
    }


    /**
     * @return void
     */
    public function it_is_initializable()
    {
        $this->shouldHaveType(OpenIdConnectDiscoverConfigurationController::class);
    }


    /**
     * @param \Zend\Diactoros\ServerRequest $request
     * @param \SimpleSAML\Modules\OpenIDConnect\Services\ConfigurationService $configurationService
     * @param \SimpleSAML\Configuration $oidcConfiguration
     * @return void
     */
    public function it_returns_openid_connect_configuration(
        ServerRequest $request,
        ConfigurationService $configurationService,
        Configuration $oidcConfiguration
    ) {
        $configurationService->getOpenIDConnectConfiguration()->shouldBeCalled()->willReturn($oidcConfiguration);
        $configurationService->getOpenIDScopes()->shouldBeCalled()->willReturn(['openid' => 'openid']);
        $oidcConfiguration->getBoolean('pkce')->shouldBeCalled()->willReturn(true);

        $configurationService->getSimpleSAMLSelfURLHost()->shouldBeCalled()->willReturn('http://localhost');
        $configurationService->getOpenIdConnectModuleURL('authorize.php')->willReturn('http://localhost/authorize.php');
        $configurationService->getOpenIdConnectModuleURL('access_token.php')->willReturn('http://localhost/access_token.php');
        $configurationService->getOpenIdConnectModuleURL('userinfo.php')->willReturn('http://localhost/userinfo.php');
        $configurationService->getOpenIdConnectModuleURL('jwks.php')->willReturn('http://localhost/jwks.php');

        $this->__invoke($request)->shouldHavePayload([
            'issuer' => 'http://localhost',
            'authorization_endpoint' => 'http://localhost/authorize.php',
            'token_endpoint' => 'http://localhost/access_token.php',
            'userinfo_endpoint' => 'http://localhost/userinfo.php',
            'jwks_uri' => 'http://localhost/jwks.php',
            'scopes_supported' => ['openid'],
            'response_types_supported' => ['code', 'token', 'id_token token'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
            'code_challenge_methods_supported' => ['plain', 'S256'],
        ]);
    }


    /**
     * @return array
     */
    public function getMatchers(): array
    {
        return [
            'havePayload' => function (JsonResponse $subject, $payload) {
                return $payload === $subject->getPayload();
            },
        ];
    }
}
