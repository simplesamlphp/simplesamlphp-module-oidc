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

use Nette\Forms\Controls\BaseControl;
use SimpleSAML\Module\oidc\Controller\Traits\AuthenticatedGetClientFromRequestTrait;
use SimpleSAML\Module\oidc\Controller\Traits\GetClientFromRequestTrait;
use SimpleSAML\Module\oidc\Entity\ClientEntity;
use SimpleSAML\Module\oidc\Factories\FormFactory;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Form\ClientForm;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\ConfigurationService;
use SimpleSAML\Module\oidc\Services\SessionMessagesService;
use SimpleSAML\Module\oidc\Services\AuthContextService;
use SimpleSAML\Utils\HTTP;
use Laminas\Diactoros\Response\RedirectResponse;
use Laminas\Diactoros\ServerRequest;

class ClientEditController
{
    use AuthenticatedGetClientFromRequestTrait;

    /**
     * @var ConfigurationService
     */
    private $configurationService;

    /**
     * @var TemplateFactory
     */
    private $templateFactory;
    /**
     * @var FormFactory
     */
    private $formFactory;

    /**
     * @var SessionMessagesService
     */
    private $messages;

    /**
     * @var AllowedOriginRepository
     */
    protected $allowedOriginRepository;

    public function __construct(
        ConfigurationService $configurationService,
        ClientRepository $clientRepository,
        AllowedOriginRepository $allowedOriginRepository,
        TemplateFactory $templateFactory,
        FormFactory $formFactory,
        SessionMessagesService $messages,
        AuthContextService $authContextService
    ) {
        $this->configurationService = $configurationService;
        $this->clientRepository = $clientRepository;
        $this->allowedOriginRepository = $allowedOriginRepository;
        $this->templateFactory = $templateFactory;
        $this->formFactory = $formFactory;
        $this->messages = $messages;
        $this->authContextService = $authContextService;
    }

    /**
     * @return \Laminas\Diactoros\Response\RedirectResponse|\SimpleSAML\XHTML\Template
     */
    public function __invoke(ServerRequest $request)
    {

        $client = $this->getClientFromRequest($request);
        $clientAllowedOrigins = $this->allowedOriginRepository->get($client->getIdentifier());

        /** @var ClientForm $form  */
        $form = $this->formFactory->build(ClientForm::class);
        $formAction = $request->withQueryParams(['client_id' =>$client->getIdentifier()])->getRequestTarget();
        $form->setAction($formAction);

        $clientData = $client->toArray();
        $clientData['allowed_origin'] = $clientAllowedOrigins;
        $form->setDefaults($clientData);
        $authedUser = $this->authContextService->isSspAdmin() ? null : $this->authContextService->getAuthUserId();

        if ($form->isSuccess()) {
            $data = $form->getValues();

            $this->clientRepository->update(ClientEntity::fromData(
                $client->getIdentifier(),
                $client->getSecret(),
                $data['name'],
                $data['description'],
                $data['redirect_uri'],
                $data['scopes'],
                (bool) $data['is_enabled'],
                (bool) $data['is_confidential'],
                $data['auth_source'],
                $client->getOwner()
            ), $authedUser);

            // Also persist allowed origins for this client.
            $this->allowedOriginRepository->set($client->getIdentifier(), $data['allowed_origin']);

            $this->messages->addMessage('{oidc:client:updated}');

            return new RedirectResponse(HTTP::addURLParameters('show.php', ['client_id' => $client->getIdentifier()]));
        }

        return $this->templateFactory->render('oidc:clients/edit.twig', [
            'form' => $form,
        ]);
    }
}
