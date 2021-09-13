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

use Laminas\Diactoros\Response\RedirectResponse;
use Laminas\Diactoros\ServerRequest;
use SimpleSAML\Module\oidc\Entity\ClientEntity;
use SimpleSAML\Module\oidc\Factories\FormFactory;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Form\ClientForm;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\AuthContextService;
use SimpleSAML\Module\oidc\Services\ConfigurationService;
use SimpleSAML\Module\oidc\Services\SessionMessagesService;
use SimpleSAML\Utils\HTTP;
use SimpleSAML\Utils\Random;

class ClientCreateController
{
    /**
     * @var ConfigurationService
     */
    private $configurationService;

    /**
     * @var ClientRepository
     */
    private $clientRepository;

    /**
     * @var \SimpleSAML\Module\oidc\Factories\TemplateFactory
     */
    private $templateFactory;

    /**
     * @var \SimpleSAML\Module\oidc\Factories\FormFactory
     */
    private $formFactory;

    /**
     * @var \SimpleSAML\Module\oidc\Services\SessionMessagesService
     */
    private $messages;

    /**
     * @var AuthContextService
     */
    private $authContextService;

    /*
     * @var AllowedOriginRepository
     */
    private $allowedOriginRepository;

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
        /** @var ClientForm $form */
        $form = $this->formFactory->build(ClientForm::class);
        $form->setAction('./new.php');


        if ($form->isSuccess()) {
            $client = $form->getValues();
            $client['id'] = Random::generateID();
            $client['secret'] = Random::generateID();
            if (!$this->authContextService->isSspAdmin()) {
                $client['owner'] = $this->authContextService->getAuthUserId();
            }

            $this->clientRepository->add(ClientEntity::fromData(
                $client['id'],
                $client['secret'],
                $client['name'],
                $client['description'],
                $client['redirect_uri'],
                $client['scopes'],
                $client['is_enabled'],
                $client['is_confidential'],
                $client['auth_source'],
                $client['owner'] ?? null
            ));

            // Also persist allowed origins for this client.
            $this->allowedOriginRepository->set($client['id'], $client['allowed_origin']);

            $this->messages->addMessage('{oidc:client:added}');

            return new RedirectResponse(HTTP::addURLParameters('show.php', ['client_id' => $client['id']]));
        }

        return $this->templateFactory->render('oidc:clients/new.twig', [
            'form' => $form,
        ]);
    }
}
