<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers\Admin;

use SimpleSAML\Locale\Translate;
use SimpleSAML\Module\oidc\Admin\Authorization;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;
use SimpleSAML\Module\oidc\Services\SessionMessagesService;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\Federation;
use Symfony\Component\HttpFoundation\Response;

class ConfigController
{
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly TemplateFactory $templateFactory,
        protected readonly Authorization $authorization,
        protected readonly DatabaseMigration $databaseMigration,
        protected readonly SessionMessagesService $sessionMessagesService,
        protected readonly Federation $federation,
        protected readonly Routes $routes,
    ) {
        $this->authorization->requireAdmin(true);
    }

    public function migrations(): Response
    {
        return $this->templateFactory->build(
            'oidc:config/migrations.twig',
            [
                'databaseMigration' => $this->databaseMigration,
            ],
            RoutesEnum::AdminMigrations->value,
        );
    }

    public function runMigrations(): Response
    {
        if ($this->databaseMigration->isMigrated()) {
            $message = Translate::noop('Database is already migrated.');
            $this->sessionMessagesService->addMessage($message);
            return $this->routes->newRedirectResponseToModuleUrl(RoutesEnum::AdminMigrations->value);
        }

        $this->databaseMigration->migrate();
        $message = Translate::noop('Database migrated successfully.');
        $this->sessionMessagesService->addMessage($message);

        return $this->routes->newRedirectResponseToModuleUrl(RoutesEnum::AdminMigrations->value);
    }

    public function protocolSettings(): Response
    {
        return $this->templateFactory->build(
            'oidc:config/protocol.twig',
            [
                'moduleConfig' => $this->moduleConfig,
            ],
            RoutesEnum::AdminConfigProtocol->value,
        );
    }

    public function federationSettings(): Response
    {
        $trustMarks = [];
        if (is_array($trustMarkTokens = $this->moduleConfig->getFederationTrustMarkTokens())) {
            $trustMarks = array_map(
                function (string $token): Federation\TrustMark {
                    return $this->federation->trustMarkFactory()->fromToken($token);
                },
                $trustMarkTokens,
            );
        }

        if (is_array($dynamicTrustMarks = $this->moduleConfig->getFederationDynamicTrustMarks())) {
            /**
             * @var non-empty-string $trustMarkType
             * @var non-empty-string $trustMarkIssuerId
             */
            foreach ($dynamicTrustMarks as $trustMarkType => $trustMarkIssuerId) {
                $trustMarkIssuerConfigurationStatement = $this->federation->entityStatementFetcher()
                    ->fromCacheOrWellKnownEndpoint($trustMarkIssuerId);

                $trustMarks[] = $this->federation->trustMarkFetcher()->fromCacheOrFederationTrustMarkEndpoint(
                    $trustMarkType,
                    $this->moduleConfig->getIssuer(),
                    $trustMarkIssuerConfigurationStatement,
                );
            }
        }

        return $this->templateFactory->build(
            'oidc:config/federation.twig',
            [
                'moduleConfig' => $this->moduleConfig,
                'trustMarks' => $trustMarks,
            ],
            RoutesEnum::AdminConfigFederation->value,
        );
    }
}
