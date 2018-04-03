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

use SimpleSAML\Modules\OpenIDConnect\Entity\ClientEntity;
use SimpleSAML\Modules\OpenIDConnect\Form\ClientForm;
use SimpleSAML\Modules\OpenIDConnect\Repositories\ClientRepository;
use SimpleSAML\Modules\OpenIDConnect\Services\FormFactory;
use SimpleSAML\Modules\OpenIDConnect\Services\SessionMessagesService;
use SimpleSAML\Modules\OpenIDConnect\Services\TemplateFactory;
use SimpleSAML\Utils\HTTP;
use SimpleSAML\Utils\Random;
use Zend\Diactoros\Response\RedirectResponse;
use Zend\Diactoros\ServerRequest;

class ClientController
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
    /**
     * @var FormFactory
     */
    private $formFactory;

    public function __construct(
        ClientRepository $clientRepository,
        TemplateFactory $templateFactory,
        SessionMessagesService $messagesService,
        FormFactory $formFactory
    ) {
        $this->clientRepository = $clientRepository;
        $this->templateFactory = $templateFactory;
        $this->messagesService = $messagesService;
        $this->formFactory = $formFactory;
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
        $client = $this->getClientFromRequest($request);

        return $this->templateFactory->render('oidc:clients/show.twig', [
            'client' => $client,
        ]);
    }

    public function new(ServerRequest $request)
    {
        $form = $this->formFactory->build(ClientForm::class);
        $form->setAction($request->getUri());

        if ($form->isSuccess()) {
            $client = $form->getValues();
            $client['id'] = Random::generateID();
            $client['secret'] = Random::generateID();

            $this->clientRepository->add(ClientEntity::fromData(
                $client['id'],
                $client['secret'],
                $client['name'],
                $client['description'],
                $client['auth_source'],
                $client['redirect_uri'],
                $client['scopes']
            ));

            $this->messagesService->addMessage('{oidc:client:added}');

            return new RedirectResponse(HTTP::addURLParameters('index.php', []));
        }

        return $this->templateFactory->render('oidc:clients/new.twig', [
            'form' => $form,
        ]);
    }

    public function edit(ServerRequest $request)
    {
        $client = $this->getClientFromRequest($request);

        $form = $this->formFactory->build(ClientForm::class);
        $form->setAction($request->getUri());
        $form->setDefaults($client->toArray());

        if ($form->isSuccess()) {
            $data = $form->getValues();

            $this->clientRepository->update(ClientEntity::fromData(
                $client->getIdentifier(),
                $client->getSecret(),
                $data['name'],
                $data['description'],
                $data['auth_source'],
                $data['redirect_uri'],
                $data['scopes']
            ));

            $this->messagesService->addMessage('{oidc:client:updated}');

            return new RedirectResponse(HTTP::addURLParameters('index.php', []));
        }

        return $this->templateFactory->render('oidc:clients/edit.twig', [
            'form' => $form,
        ]);
    }

    public function delete(ServerRequest $request)
    {
        $client = $this->getClientFromRequest($request);
        $body = $request->getParsedBody();
        $clientSecret = $body['secret'] ?? null;

        if ('POST' === mb_strtoupper($request->getMethod())) {
            if (!$clientSecret) {
                throw new \SimpleSAML_Error_BadRequest('Client secret is missing.');
            }

            if ($clientSecret !== $client->getSecret()) {
                throw new \SimpleSAML_Error_BadRequest('Client secret is invalid.');
            }

            $this->clientRepository->delete($client);
            $this->messagesService->addMessage('{oidc:client:removed}');

            return new RedirectResponse(HTTP::addURLParameters('index.php', []));
        }

        return $this->templateFactory->render('oidc:clients/delete.twig', [
            'client' => $client,
        ]);
    }

    public function reset(ServerRequest $request)
    {
        $client = $this->getClientFromRequest($request);
        $body = $request->getParsedBody();
        $clientSecret = $body['secret'] ?? null;

        if ('POST' === mb_strtoupper($request->getMethod())) {
            if (!$clientSecret) {
                throw new \SimpleSAML_Error_BadRequest('Client secret is missing.');
            }

            if ($clientSecret !== $client->getSecret()) {
                throw new \SimpleSAML_Error_BadRequest('Client secret is invalid.');
            }

            $client->restoreSecret(Random::generateID());

            $this->clientRepository->update($client);
            $this->messagesService->addMessage('{oidc:client:secret_updated}');

            return new RedirectResponse(HTTP::addURLParameters('show.php', ['id' => $client->getIdentifier()]));
        }

        return new RedirectResponse(HTTP::addURLParameters('show.php', ['id' => $client->getIdentifier()]));
    }

    /**
     * @param ServerRequest $request
     *
     * @throws \SimpleSAML_Error_BadRequest
     * @throws \SimpleSAML_Error_NotFound
     *
     * @return null|\SimpleSAML\Modules\OpenIDConnect\Entity\ClientEntity
     */
    private function getClientFromRequest(ServerRequest $request)
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

        return $client;
    }
}
