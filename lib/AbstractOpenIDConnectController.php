<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * (c) Sergio Gómez <sergio@uco.es>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Modules\OpenIDConnect;

use League\OAuth2\Server\Exception\OAuthServerException;
use SimpleSAML\Modules\OpenIDConnect\Repositories\ClientRepository;
use SimpleSAML\Modules\OpenIDConnect\Services\Container;
use Zend\Diactoros\Response\JsonResponse;
use Zend\Diactoros\Response\SapiEmitter;
use Zend\Diactoros\ServerRequest;

abstract class AbstractOpenIDConnectController
{
    /**
     * @var Container
     */
    protected $container;

    public function __construct(Container $container)
    {
        $this->container = $container;
    }

    /**
     * @param ServerRequest $request
     *
     * @throws \Psr\Container\NotFoundExceptionInterface
     * @throws \SimpleSAML_Error_BadRequest
     * @throws \SimpleSAML_Error_Exception
     * @throws \SimpleSAML_Error_NotFound
     *
     * @return \SimpleSAML\Modules\OpenIDConnect\Entity\ClientEntity
     */
    protected function getClientFromRequest(ServerRequest $request)
    {
        $params = $request->getQueryParams();
        $clientId = $params['id'] ?? null;

        if (!$clientId) {
            throw new \SimpleSAML_Error_BadRequest('Client id is missing.');
        }

        $client = $this->container->get(ClientRepository::class)->findById($clientId);
        if (!$client) {
            throw new \SimpleSAML_Error_NotFound('Client not found.');
        }

        return $client;
    }

    protected function enableJsonExceptionResponse()
    {
        set_exception_handler(function (\Throwable $t) {
            if ($t instanceof OAuthServerException) {
                $error['error'] = [
                    'code' => $t->getHttpStatusCode(),
                    'message' => $t->getMessage(),
                    'hint' => $t->getHint(),
                ];
            } else {
                $error['error'] = [
                    'code' => 500,
                    'message' => $t->getMessage(),
                ];
            }

            $response = new JsonResponse($error, 500);
            $emitter = new SapiEmitter();
            $emitter->emit($response);
        });
    }
}
