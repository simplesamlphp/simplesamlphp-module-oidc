<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controller;

use SimpleSAML\Locale\Translate;
use SimpleSAML\Module\oidc\Admin\Authorization;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;
use SimpleSAML\Module\oidc\Services\SessionMessagesService;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;

class AdminController
{
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly TemplateFactory $templateFactory,
        protected readonly Authorization $authorization,
        protected readonly DatabaseMigration $databaseMigration,
        protected readonly SessionMessagesService $sessionMessagesService,
    ) {
        $this->authorization->requireSspAdmin(true);
    }

    public function configOverview(): Response
    {
        return $this->templateFactory->build(
            'oidc:config/overview.twig',
            [
                'moduleConfig' => $this->moduleConfig,
                'databaseMigration' => $this->databaseMigration,
            ],
            RoutesEnum::AdminConfigOverview->value,
        );
    }

    public function runMigrations(): Response
    {
        if ($this->databaseMigration->isMigrated()) {
            $message = Translate::noop('Database is already migrated.');
            $this->sessionMessagesService->addMessage($message);
            return new RedirectResponse($this->moduleConfig->getModuleUrl(RoutesEnum::AdminConfigOverview->value));
        }

        $this->databaseMigration->migrate();
        $message = Translate::noop('Database migrated successfully.');
        $this->sessionMessagesService->addMessage($message);

        return new RedirectResponse($this->moduleConfig->getModuleUrl(RoutesEnum::AdminConfigOverview->value));
    }
}
