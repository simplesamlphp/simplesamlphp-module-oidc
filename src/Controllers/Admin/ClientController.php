<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers\Admin;

use SimpleSAML\Module\oidc\Admin\Authorization;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use Symfony\Component\HttpFoundation\Response;

class ClientController
{
    public function __construct(
        protected readonly TemplateFactory $templateFactory,
        protected readonly Authorization $authorization,
    ) {
        $this->authorization->requireSspAdmin(true);
    }
    public function index(): Response
    {
        return $this->templateFactory->build(
            'oidc:clients.twig',
            [
                //
            ],
            RoutesEnum::AdminClients->value,
        );
    }
}
