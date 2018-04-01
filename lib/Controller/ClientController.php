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
use SimpleSAML\Modules\OpenIDConnect\Services\TemplateFactory;
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

    public function __construct(ClientRepository $clientRepository, TemplateFactory $templateFactory)
    {
        $this->clientRepository = $clientRepository;
        $this->templateFactory = $templateFactory;
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
}
