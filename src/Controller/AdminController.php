<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controller;

use SimpleSAML\Module\oidc\Admin\Authorization;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use Symfony\Component\HttpFoundation\Response;

class AdminController
{
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly TemplateFactory $templateFactory,
        protected readonly Authorization $authorization,
    ) {
        $this->authorization->requireSspAdmin(true);
    }

    public function configOverview(): Response
    {
        return $this->templateFactory->build(
            'oidc:config/overview.twig',
            ['moduleConfig' => $this->moduleConfig],
            RoutesEnum::AdminConfigOverview->value,
        );
    }
}
