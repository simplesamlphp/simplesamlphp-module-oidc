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

namespace SimpleSAML\Module\oidc\Controller\Client;

use Laminas\Diactoros\Response\RedirectResponse;
use Laminas\Diactoros\ServerRequest;
use SimpleSAML\Error\BadRequest;
use SimpleSAML\Error\Exception;
use SimpleSAML\Error\NotFound;
use SimpleSAML\Module\oidc\Controller\Traits\AuthenticatedGetClientFromRequestTrait;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\AuthContextService;
use SimpleSAML\Module\oidc\Services\SessionMessagesService;
use SimpleSAML\Utils\HTTP;
use SimpleSAML\Utils\Random;

class ResetSecretController
{
    use AuthenticatedGetClientFromRequestTrait;

    public function __construct(
        ClientRepository $clientRepository,
        private readonly SessionMessagesService $messages,
        AuthContextService $authContextService
    ) {
        $this->clientRepository = $clientRepository;
        $this->authContextService = $authContextService;
    }

    /**
     * @throws BadRequest
     * @throws NotFound
     * @throws Exception
     * @throws \Exception
     */
    public function __invoke(ServerRequest $request): RedirectResponse
    {
        $client = $this->getClientFromRequest($request);
        $body = $request->getParsedBody();
        $clientSecret = empty($body['secret']) ? null : (string)$body['secret'];

        if ('POST' === mb_strtoupper($request->getMethod())) {
            if (!$clientSecret) {
                throw new BadRequest('Client secret is missing.');
            }

            if ($clientSecret !== $client->getSecret()) {
                throw new BadRequest('Client secret is invalid.');
            }

            $client->restoreSecret((new Random())->generateID());
            $authedUser = $this->authContextService->isSspAdmin() ? null : $this->authContextService->getAuthUserId();
            $this->clientRepository->update($client, $authedUser);
            $this->messages->addMessage('{oidc:client:secret_updated}');
        }

        return new RedirectResponse(
            (new HTTP())->addURLParameters('show.php', ['client_id' => $client->getIdentifier()])
        );
    }
}
