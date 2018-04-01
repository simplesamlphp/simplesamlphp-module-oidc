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

use SimpleSAML\Modules\OpenIDConnect\Repositories\ClientRepository;
use SimpleSAML\Modules\OpenIDConnect\Services\SessionMessagesService;
use SimpleSAML\Modules\OpenIDConnect\Services\TemplateFactory;
use SimpleSAML\Modules\OpenIDConnect\Templates\RedirectResponse;
use Zend\Diactoros\ServerRequest;

final class ClientController
{
    /**
     * @var ClientRepository
     */
    private $clientRepository;
    /**
     * @var TemplateFactory
     */
    private $templateFactory;
    /**
     * @var SessionMessagesService
     */
    private $messagesService;

    public function __construct(ClientRepository $clientRepository, TemplateFactory $templateFactory, SessionMessagesService $messagesService)
    {
        $this->clientRepository = $clientRepository;
        $this->templateFactory = $templateFactory;
        $this->messagesService = $messagesService;
    }

    public function index(ServerRequest $request)
    {
        $clients = $this->clientRepository->findAll();

        return $this->templateFactory->render('oidc:clients/index.twig', [
            'clients' => $clients,
        ]);
    }

    public function show(ServerRequest $request)
    {
        $params = $request->getQueryParams();
        $clientId = $params['id'] ?? null;

        if (!$clientId) {
            throw new \SimpleSAML_Error_BadRequest('Client id is missing.');
        }

        $client = $this->clientRepository->findById($clientId);
        if (!$client) {
            throw new \SimpleSAML_Error_NotFound('Client not found.');
        }

        return $this->templateFactory->render('oidc:clients/show.twig', [
            'client' => $client,
        ]);
    }

    public function delete(ServerRequest $request)
    {
        $params = $request->getQueryParams();
        $clientId = $params['id'] ?? null;
        $body = $request->getParsedBody();
        $clientSecret = $body['secret'] ?? null;

        if (!$clientId) {
            throw new \SimpleSAML_Error_BadRequest('Client id is missing.');
        }

        $client = $this->clientRepository->findById($clientId);
        if (!$client) {
            throw new \SimpleSAML_Error_NotFound('Client not found.');
        }

        if ('POST' === mb_strtoupper($request->getMethod())) {
            if (!$clientSecret) {
                throw new \SimpleSAML_Error_BadRequest('Client secret is missing.');
            }

            if ($clientSecret !== $client->getSecret()) {
                throw new \SimpleSAML_Error_BadRequest('Client secret is invalid.');
            }

            $this->clientRepository->delete($client);
            $this->messagesService->addMessage('{oidc:client:removed}');

            return new RedirectResponse('index.php');
        }

        return $this->templateFactory->render('oidc:clients/delete.twig', [
            'client' => $client,
        ]);
    }
}
