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

use JsonException;
use SimpleSAML\Error\Exception;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Error\BadRequest;
use SimpleSAML\Error\NotFound;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\AuthContextService;

trait AuthenticatedGetClientFromRequestTrait
{
    protected ClientRepository $clientRepository;

    private AuthContextService $authContextService;

    /**
     * @throws BadRequest|NotFound|Exception|OidcServerException|JsonException
     */
    protected function getClientFromRequest(ServerRequestInterface $request): ClientEntityInterface
    {
        $params = $request->getQueryParams();
        $clientId = empty($params['client_id']) ? null : (string)$params['client_id'];

        if (!is_string($clientId)) {
            throw new BadRequest('Client id is missing.');
        }
        $authedUser = null;
        if (!$this->authContextService->isSspAdmin()) {
            $authedUser = $this->authContextService->getAuthUserId();
        }
        $client = $this->clientRepository->findById($clientId, $authedUser);
        if (!$client) {
            throw new NotFound('Client not found.');
        }

        return $client;
    }
}
