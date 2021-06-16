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

use Laminas\Diactoros\Response\RedirectResponse;
use Laminas\Diactoros\ServerRequest;
use SimpleSAML\Modules\OpenIDConnect\Entity\ClientEntity;
use SimpleSAML\Modules\OpenIDConnect\Factories\FormFactory;
use SimpleSAML\Modules\OpenIDConnect\Factories\TemplateFactory;
use SimpleSAML\Modules\OpenIDConnect\Form\ClientForm;
use SimpleSAML\Modules\OpenIDConnect\Repositories\ClientRepository;
use SimpleSAML\Modules\OpenIDConnect\Services\AuthContextService;
use SimpleSAML\Modules\OpenIDConnect\Services\ConfigurationService;
use SimpleSAML\Modules\OpenIDConnect\Services\SessionMessagesService;
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
     * @var \SimpleSAML\Modules\OpenIDConnect\Factories\TemplateFactory
     */
    private $templateFactory;

    /**
     * @var \SimpleSAML\Modules\OpenIDConnect\Factories\FormFactory
     */
    private $formFactory;

    /**
     * @var \SimpleSAML\Modules\OpenIDConnect\Services\SessionMessagesService
     */
    private $messages;

    /**
     * @var AuthContextService
     */
    private $authContextService;

    public function __construct(
        ConfigurationService $configurationService,
        ClientRepository $clientRepository,
        TemplateFactory $templateFactory,
        FormFactory $formFactory,
        SessionMessagesService $messages,
        AuthContextService $authContextService
    ) {
        $this->configurationService = $configurationService;
        $this->clientRepository = $clientRepository;
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
        $form = $this->formFactory->build(ClientForm::class);
        $formAction = $this->configurationService->getOpenIdConnectModuleURL('clients/new.php');
        $form->setAction($formAction);


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

            $this->messages->addMessage('{oidc:client:added}');

            return new RedirectResponse(HTTP::addURLParameters('show.php', ['client_id' => $client['id']]));
        }

        return $this->templateFactory->render('oidc:clients/new.twig', [
            'form' => $form,
        ]);
    }
}
