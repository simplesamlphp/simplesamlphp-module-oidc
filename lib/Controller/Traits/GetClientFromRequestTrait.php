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

namespace SimpleSAML\Modules\OpenIDConnect\Controller\Traits;

use SimpleSAML\Modules\OpenIDConnect\Entity\ClientEntity;
use SimpleSAML\Modules\OpenIDConnect\Repositories\ClientRepository;
use Zend\Diactoros\ServerRequest;

trait GetClientFromRequestTrait
{
    /**
     * @var ClientRepository
     */
    protected $clientRepository;

    /**
     * @throws \SimpleSAML_Error_BadRequest
     * @throws \SimpleSAML_Error_NotFound
     *
     * @return ClientEntity
     */
    protected function getClientFromRequest(ServerRequest $request)
    {
        $params = $request->getQueryParams();
        $clientId = $params['client_id'] ?? null;

        if (!$clientId) {
            throw new \SimpleSAML_Error_BadRequest('Client id is missing.');
        }

        $client = $this->clientRepository->findById($clientId);
        if (!$client) {
            throw new \SimpleSAML_Error_NotFound('Client not found.');
        }

        return $client;
    }
}
