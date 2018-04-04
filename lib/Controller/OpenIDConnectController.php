<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * (c) Sergio Gómez <sergio@uco.es>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Modules\OpenIDConnect\Controller;

use SimpleSAML\Modules\OpenIDConnect\AbstractOpenIDConnectController;
use SimpleSAML\Modules\OpenIDConnect\Services\ConfigurationService;
use SimpleSAML\Modules\OpenIDConnect\Services\JsonWebKeySetService;
use Zend\Diactoros\Response\JsonResponse;
use Zend\Diactoros\ServerRequest;

class OpenIDConnectController extends AbstractOpenIDConnectController
{
    /**
     * @var JsonWebKeySetService
     */
    private $jsonWebKeySet;
    /**
     * @var ConfigurationService
     */
    private $configurationService;

    public function __construct(JsonWebKeySetService $jsonWebKeySet, ConfigurationService $configurationService)
    {
        parent::__construct();

        $this->jsonWebKeySet = $jsonWebKeySet;
        $this->configurationService = $configurationService;
    }

    public function jwks(ServerRequest $request)
    {
        return new JsonResponse([
            'keys' => $this->jsonWebKeySet->keys(),
        ]);
    }

    public function configuration(ServerRequest $request)
    {
        $scopes = $this->configurationService->getOpenIDConnectConfiguration()->getArray('scopes');
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
