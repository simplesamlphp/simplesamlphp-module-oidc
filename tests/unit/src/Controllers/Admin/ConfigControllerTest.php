<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers\Admin;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Admin\Authorization;
use SimpleSAML\Module\oidc\Controllers\Admin\ConfigController;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;
use SimpleSAML\Module\oidc\Services\SessionMessagesService;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\Federation\Factories\TrustMarkFactory;

#[CoversClass(ConfigController::class)]
class ConfigControllerTest extends TestCase
{
    protected MockObject $moduleConfigMock;
    protected MockObject $templateFactoryMock;
    protected MockObject $authorizationMock;
    protected MockObject $databaseMigrationMock;
    protected MockObject $sessionMessagesServiceMock;
    protected MockObject $federationMock;
    protected MockObject $routesMock;
    protected MockObject $trustMarkFactoryMock;
    protected MockObject $entityStatementFetcherMock;
    protected MockObject $trustMarkFetcherMock;

    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->templateFactoryMock = $this->createMock(TemplateFactory::class);
        $this->authorizationMock = $this->createMock(Authorization::class);
        $this->databaseMigrationMock = $this->createMock(DatabaseMigration::class);
        $this->sessionMessagesServiceMock = $this->createMock(SessionMessagesService::class);
        $this->federationMock = $this->createMock(Federation::class);
        $this->routesMock = $this->createMock(Routes::class);

        $this->trustMarkFactoryMock = $this->createMock(TrustMarkFactory::class);
        $this->federationMock->method('trustMarkFactory')->willReturn($this->trustMarkFactoryMock);

        $this->entityStatementFetcherMock = $this->createMock(Federation\EntityStatementFetcher::class);
        $this->federationMock->method('entityStatementFetcher')->willReturn($this->entityStatementFetcherMock);

        $this->trustMarkFetcherMock = $this->createMock(Federation\TrustMarkFetcher::class);
        $this->federationMock->method('trustMarkFetcher')->willReturn($this->trustMarkFetcherMock);
    }

    public function sut(
        ?ModuleConfig $moduleConfig = null,
        ?TemplateFactory $templateFactory = null,
        ?Authorization $authorization = null,
        ?DatabaseMigration $databaseMigration = null,
        ?SessionMessagesService $sessionMessagesService = null,
        ?Federation $federation = null,
        ?Routes $routes = null,
    ): ConfigController {
        $moduleConfig ??= $this->moduleConfigMock;
        $templateFactory ??= $this->templateFactoryMock;
        $authorization ??= $this->authorizationMock;
        $databaseMigration ??= $this->databaseMigrationMock;
        $sessionMessagesService ??= $this->sessionMessagesServiceMock;
        $federation ??= $this->federationMock;
        $routes ??= $this->routesMock;

        return new ConfigController(
            $moduleConfig,
            $templateFactory,
            $authorization,
            $databaseMigration,
            $sessionMessagesService,
            $federation,
            $routes,
        );
    }

    public function testCanCreateInstance(): void
    {
        $this->authorizationMock->expects($this->once())->method('requireAdmin');
        $this->assertInstanceOf(ConfigController::class, $this->sut());
    }

    public function testCanShowMigrationsScreen(): void
    {
        $this->templateFactoryMock->expects($this->once())->method('build')
            ->with('oidc:config/migrations.twig');

        $this->sut()->migrations();
    }

    public function testCanRunMigrations(): void
    {
        $this->databaseMigrationMock->expects($this->once())->method('migrate');
        $this->sessionMessagesServiceMock->expects($this->once())->method('addMessage')
            ->with($this->stringContains('migrated'));

        $this->sut()->runMigrations();
    }

    public function testWontRunMigrationsIfAlreadyMigrated(): void
    {
        $this->databaseMigrationMock->expects($this->once())->method('isMigrated')->willReturn(true);
        $this->databaseMigrationMock->expects($this->never())->method('migrate');

        $this->sut()->runMigrations();
    }

    public function testCanShowProtocolSettingsScreen(): void
    {
        $this->templateFactoryMock->expects($this->once())->method('build')
            ->with('oidc:config/protocol.twig');

        $this->sut()->protocolSettings();
    }

    public function testCanShowFederationSettingsScreen(): void
    {
        $this->templateFactoryMock->expects($this->once())->method('build')
            ->with('oidc:config/federation.twig');

        $this->sut()->federationSettings();
    }

    public function testCanIncludeTrustMarksInFederationSettings(): void
    {
        $this->moduleConfigMock->method('getFederationTrustMarkTokens')->willReturn(['token']);
        $this->trustMarkFactoryMock->expects($this->once())->method('fromToken')
            ->with($this->stringContains('token'));

        $this->templateFactoryMock->expects($this->once())->method('build')
            ->with('oidc:config/federation.twig');

        $this->sut()->federationSettings();
    }

    public function testCanIncludeDynamicTrustMarksInFederationSettings(): void
    {
        $this->moduleConfigMock->method('getIssuer')->willReturn('issuer-id');
        $this->moduleConfigMock->method('getFederationDynamicTrustMarks')
            ->willReturn(['trust-mark-id' => 'trust-mark-issuer-id']);

        $this->entityStatementFetcherMock->expects($this->once())->method('fromCacheOrWellKnownEndpoint')
            ->with('trust-mark-issuer-id');

        $this->trustMarkFetcherMock->expects($this->once())->method('fromCacheOrFederationTrustMarkEndpoint')
            ->with(
                'trust-mark-id',
                'issuer-id',
            );

        $this->templateFactoryMock->expects($this->once())->method('build')
            ->with('oidc:config/federation.twig');

        $this->sut()->federationSettings();
    }
}
