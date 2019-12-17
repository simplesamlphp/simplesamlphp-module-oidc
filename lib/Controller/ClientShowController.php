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

use SimpleSAML\Modules\OpenIDConnect\Controller\Traits\GetClientFromRequestTrait;
use SimpleSAML\Modules\OpenIDConnect\Factories\TemplateFactory;
use SimpleSAML\Modules\OpenIDConnect\Repositories\ClientRepository;
use Zend\Diactoros\ServerRequest;

class ClientShowController
{
    use GetClientFromRequestTrait;

    /**
     * @var TemplateFactory
     */
    private $templateFactory;


    /**
     * @param \SimpleSAML\Modules\OpenIDConnect\Repositories\ClientRepository $clientRepository
     * @param \SimpleSAML\Modules\OpenIDConnect\Factories\TemplateFactory $templateFactory
     */
    public function __construct(ClientRepository $clientRepository, TemplateFactory $templateFactory)
    {
        $this->clientRepository = $clientRepository;
        $this->templateFactory = $templateFactory;
    }


    /**
     * @param \Zend\Diactoros\ServerRequest $request
     * @return \SimpleSAML\XHTML\Template
     */
    public function __invoke(ServerRequest $request)
    {
        $client = $this->getClientFromRequest($request);

        return $this->templateFactory->render('oidc:clients/show.twig', [
            'client' => $client,
        ]);
    }
}
