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

namespace SimpleSAML\Module\oidc\Controller;

use SimpleSAML\Error\BadRequest;
use SimpleSAML\Module\oidc\Controller\Traits\AuthenticatedGetClientFromRequestTrait;
use SimpleSAML\Module\oidc\Controller\Traits\GetClientFromRequestTrait;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\SessionMessagesService;
use SimpleSAML\Module\oidc\Services\AuthContextService;
use SimpleSAML\Utils\HTTP;
use SimpleSAML\Utils\Random;
use Laminas\Diactoros\Response\RedirectResponse;
use Laminas\Diactoros\ServerRequest;

class ClientResetSecretController
{
    use AuthenticatedGetClientFromRequestTrait;

    /**
     * @var SessionMessagesService
     */
    private $messages;

    public function __construct(
        ClientRepository $clientRepository,
        SessionMessagesService $messages,
        AuthContextService $authContextService
    ) {
        $this->clientRepository = $clientRepository;
        $this->messages = $messages;
        $this->authContextService = $authContextService;
    }

    public function __invoke(ServerRequest $request): RedirectResponse
    {
        $client = $this->getClientFromRequest($request);
        $body = $request->getParsedBody();
        $clientSecret = $body['secret'] ?? null;

        if ('POST' === mb_strtoupper($request->getMethod())) {
            if (!$clientSecret) {
                throw new BadRequest('Client secret is missing.');
            }

            if ($clientSecret !== $client->getSecret()) {
                throw new BadRequest('Client secret is invalid.');
            }

            $client->restoreSecret(Random::generateID());
            $authedUser = $this->authContextService->isSspAdmin() ? null : $this->authContextService->getAuthUserId();
            $this->clientRepository->update($client, $authedUser);
            $this->messages->addMessage('{oidc:client:secret_updated}');
        }

        return new RedirectResponse(HTTP::addURLParameters('show.php', ['client_id' => $client->getIdentifier()]));
    }
}
