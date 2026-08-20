<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers\Admin;

use SimpleSAML\Locale\Translate;
use SimpleSAML\Module\oidc\Admin\Authorization;
use SimpleSAML\Module\oidc\Admin\ConfigOverview\FederationOverviewBuilder;
use SimpleSAML\Module\oidc\Admin\ConfigOverview\GeneralOverviewBuilder;
use SimpleSAML\Module\oidc\Admin\ConfigOverview\ProtocolOverviewBuilder;
use SimpleSAML\Module\oidc\Admin\ConfigOverview\VciOverviewBuilder;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\Factories\FederationFactory;
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
        // The factory rather than the Federation itself, so that building one is deferred to the single
        // screen that needs it. Constructing a Federation resolves the outbound destination policy, and a
        // malformed outbound option would otherwise make this whole controller unresolvable - taking down
        // the Configuration screens, which are exactly what an administrator opens to find such an option.
        protected readonly FederationFactory $federationFactory,
        protected readonly Routes $routes,
        protected readonly GeneralOverviewBuilder $generalOverviewBuilder,
        protected readonly ProtocolOverviewBuilder $protocolOverviewBuilder,
        protected readonly FederationOverviewBuilder $federationOverviewBuilder,
        protected readonly VciOverviewBuilder $vciOverviewBuilder,
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

    public function generalSettings(): Response
    {
        return $this->templateFactory->build(
            'oidc:config/general.twig',
            [
                'moduleConfig' => $this->moduleConfig,
                'sections' => $this->generalOverviewBuilder->build(),
            ],
            RoutesEnum::AdminConfigGeneral->value,
        );
    }

    /**
     * @throws \Exception
     */
    public function protocolSettings(): Response
    {
        return $this->templateFactory->build(
            'oidc:config/protocol.twig',
            [
                'moduleConfig' => $this->moduleConfig,
                'sections' => $this->protocolOverviewBuilder->build(),
            ],
            RoutesEnum::AdminConfigProtocol->value,
        );
    }

    public function federationSettings(): Response
    {
        $trustMarks = [];

        try {
            $federation = $this->federationFactory->build();
        } catch (\Throwable) {
            // This screen still has plenty to report without a Federation, and the configuration that
            // prevented one from being built is itself among what it reports: the option at fault gets a
            // warning on its own row below, from a builder that logs the detail rather than rendering it.
            // The exception message is deliberately not shown here for the same reason - it comes from
            // config validation and from key material loading, so it can quote configured values back.
            $this->sessionMessagesService->addMessage(
                Translate::noop(
                    'Federation tooling could not be built from the current configuration, so trust ' .
                    'marks are not shown. Check the federation options below, and the outbound ' .
                    'destination policy on the Protocol configuration screen, which federation fetches ' .
                    'also depend on.',
                ),
            );

            return $this->templateFactory->build(
                'oidc:config/federation.twig',
                [
                    'moduleConfig' => $this->moduleConfig,
                    'sections' => $this->federationOverviewBuilder->build($trustMarks),
                ],
                RoutesEnum::AdminConfigFederation->value,
            );
        }

        if (is_array($trustMarkTokens = $this->moduleConfig->getFederationTrustMarkTokens())) {
            $trustMarks = array_map(
                function (string $token) use ($federation): Federation\TrustMark {
                    return $federation->trustMarkFactory()->fromToken($token);
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
                try {
                    $trustMarkIssuerConfigurationStatement = $federation->entityStatementFetcher()
                        ->fromCacheOrWellKnownEndpoint($trustMarkIssuerId);

                    $trustMarks[] = $federation->trustMarkFetcher()->fromCacheOrFederationTrustMarkEndpoint(
                        $trustMarkType,
                        $this->moduleConfig->getIssuer(),
                        $trustMarkIssuerConfigurationStatement,
                    );
                } catch (\Exception $e) {
                    // Added as two messages rather than one concatenated string. The template
                    // translates each message whole, so a sentence with identifiers and an exception
                    // spliced into it can never match its catalog entry -- it would be marked for
                    // translation and then silently never translated. The detail, which is not
                    // translatable in any case, goes on its own line below it.
                    $this->sessionMessagesService->addMessage(
                        Translate::noop('Error fetching dynamic trust mark:'),
                    );
                    $this->sessionMessagesService->addMessage(
                        "trust_mark_type => $trustMarkType, issuer_id => $trustMarkIssuerId. " .
                        $e->getMessage(),
                    );
                }
            }
        }

        return $this->templateFactory->build(
            'oidc:config/federation.twig',
            [
                'moduleConfig' => $this->moduleConfig,
                'sections' => $this->federationOverviewBuilder->build($trustMarks),
            ],
            RoutesEnum::AdminConfigFederation->value,
        );
    }

    /**
     * @throws \Exception
     */
    public function verifiableCredentialSettings(): Response
    {
        return $this->templateFactory->build(
            'oidc:config/verifiable-credential.twig',
            [
                'moduleConfig' => $this->moduleConfig,
                'sections' => $this->vciOverviewBuilder->build(),
            ],
            RoutesEnum::AdminConfigVerifiableCredential->value,
        );
    }
}
