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

namespace SimpleSAML\Modules\OpenIDConnect\Controller;

use SimpleSAML\Modules\OpenIDConnect\Repositories\ScopeRepository;
use SimpleSAML\Modules\OpenIDConnect\Services\ConfigurationService;
use Zend\Diactoros\Response\JsonResponse;
use Zend\Diactoros\ServerRequest;

class OpenIdConnectDiscoverConfigurationController
{
    /**
     * @var ConfigurationService
     */
    private $configurationService;
    /**
     * @var ScopeRepository
     */
    private $scopeRepository;

    public function __construct(
        ConfigurationService $configurationService,
        ScopeRepository $scopeRepository
    )
    {
        $this->configurationService = $configurationService;
        $this->scopeRepository = $scopeRepository;
    }

    public function __invoke(ServerRequest $serverRequest)
    {
        $scopes = $this->scopeRepository->findAll();
        $pkceIsEnabled = $this->configurationService->getOpenIDConnectConfiguration()->getBoolean('pkce');

        $metadata['issuer'] = $this->configurationService->getSimpleSAMLSelfURLHost();
        $metadata['authorization_endpoint'] = $this->configurationService->getOpenIdConnectModuleURL('authorize.php');
        $metadata['token_endpoint'] = $this->configurationService->getOpenIdConnectModuleURL('access_token.php');
        $metadata['userinfo_endpoint'] = $this->configurationService->getOpenIdConnectModuleURL('userinfo.php');
        $metadata['jwks_uri'] = $this->configurationService->getOpenIdConnectModuleURL('jwks.php');
        $metadata['scopes_supported'] = array_keys($scopes);
        $metadata['response_types_supported'] = ['code', 'token', 'id_token token'];
        $metadata['subject_types_supported'] = ['public'];
        $metadata['id_token_signing_alg_values_supported'] = ['RS256'];
        if ($pkceIsEnabled) {
            $metadata['code_challenge_methods_supported'] = ['plain', 'S256'];
        }

        return new JsonResponse($metadata);
    }
}
