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

use SimpleSAML\Modules\OpenIDConnect\OpenIDConnectController;
use SimpleSAML\Modules\OpenIDConnect\Services\JsonWebKeySetService;
use Zend\Diactoros\Response\JsonResponse;
use Zend\Diactoros\ServerRequest;

class JwksOpenIDConnectController extends OpenIDConnectController
{
    /**
     * @var JsonWebKeySetService
     */
    private $jsonWebKeySet;

    public function __construct(JsonWebKeySetService $jsonWebKeySet)
    {
        parent::__construct();

        $this->jsonWebKeySet = $jsonWebKeySet;
    }

    public function index(ServerRequest $request)
    {
        return new JsonResponse([
            'keys' => $this->jsonWebKeySet->keys(),
        ]);
    }
}
