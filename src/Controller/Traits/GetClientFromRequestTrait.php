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

namespace SimpleSAML\Module\oidc\Controller\Traits;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Error\BadRequest;
use SimpleSAML\Error\NotFound;
use SimpleSAML\Module\oidc\Entity\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;

trait GetClientFromRequestTrait
{
    /**
     * @var ClientRepository
     */
    protected $clientRepository;

    /**
     * @throws BadRequest
     * @throws NotFound
     */
    protected function getClientFromRequest(ServerRequestInterface $request): ClientEntityInterface
    {
        $params = $request->getQueryParams();
        $clientId = $params['client_id'] ?? null;

        if (!$clientId) {
            throw new BadRequest('Client id is missing.');
        }

        $client = $this->clientRepository->findById($clientId);
        if (!$client) {
            throw new NotFound('Client not found.');
        }

        return $client;
    }
}
