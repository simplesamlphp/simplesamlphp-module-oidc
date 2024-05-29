<?php

declare(strict_types=1);

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
use SimpleSAML\Error;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;

trait GetClientFromRequestTrait
{
    protected ClientRepository $clientRepository;

    /**
     * @throws \JsonException
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Error\NotFound
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    protected function getClientFromRequest(ServerRequestInterface $request): ClientEntityInterface
    {
        $params = $request->getQueryParams();
        $clientId = empty($params['client_id']) ? null : (string)$params['client_id'];

        if (!is_string($clientId)) {
            throw new Error\BadRequest('Client id is missing.');
        }

        $client = $this->clientRepository->findById($clientId);
        if (!$client) {
            throw new Error\NotFound('Client not found.');
        }

        return $client;
    }
}
