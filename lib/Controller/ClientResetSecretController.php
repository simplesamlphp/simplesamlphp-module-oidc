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

use SimpleSAML\Error\BadRequest;
use SimpleSAML\Modules\OpenIDConnect\Controller\Traits\GetClientFromRequestTrait;
use SimpleSAML\Modules\OpenIDConnect\Repositories\ClientRepository;
use SimpleSAML\Modules\OpenIDConnect\Services\SessionMessagesService;
use SimpleSAML\Utils\HTTP;
use SimpleSAML\Utils\Random;
use Laminas\Diactoros\Response\RedirectResponse;
use Laminas\Diactoros\ServerRequest;

class ClientResetSecretController
{
    use GetClientFromRequestTrait;

    /**
     * @var SessionMessagesService
     */
    private $messages;

    public function __construct(ClientRepository $clientRepository, SessionMessagesService $messages)
    {
        $this->clientRepository = $clientRepository;
        $this->messages = $messages;
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

            $this->clientRepository->update($client);
            $this->messages->addMessage('{oidc:client:secret_updated}');
        }

        return new RedirectResponse(HTTP::addURLParameters('show.php', ['client_id' => $client->getIdentifier()]));
    }
}
