<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers\Federation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Controllers\Federation\EntityStatementController;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\JsonWebKeySetService;
use SimpleSAML\Module\oidc\Services\JsonWebTokenBuilderService;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Services\OpMetadataService;
use SimpleSAML\Module\oidc\Utils\FederationCache;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\Federation;

#[CoversClass(EntityStatementController::class)]
class EntityStatementControllerTest extends TestCase
{
    protected MockObject $moduleConfigMock;
    protected MockObject $jsonWebTokenBuilderServiceMock;
    protected MockObject $jsonWebKeySetServiceMock;
    protected MockObject $opMetadataServiceMock;
    protected MockObject $clientRepositoryMock;
    protected MockObject $helpersMock;
    protected MockObject $routesMock;
    protected MockObject $federationMock;
    protected MockObject $loggerServiceMock;
    protected MockObject $federationCacheMock;

    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->jsonWebTokenBuilderServiceMock = $this->createMock(JsonWebTokenBuilderService::class);
        $this->jsonWebKeySetServiceMock = $this->createMock(JsonWebKeySetService::class);
        $this->opMetadataServiceMock = $this->createMock(OpMetadataService::class);
        $this->clientRepositoryMock = $this->createMock(ClientRepository::class);
        $this->helpersMock = $this->createMock(Helpers::class);
        $this->routesMock = $this->createMock(Routes::class);
        $this->federationMock = $this->createMock(Federation::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        $this->federationCacheMock = $this->createMock(FederationCache::class);
    }

    protected function sut(
        ?ModuleConfig $moduleConfig = null,
        ?JsonWebTokenBuilderService $jsonWebTokenBuilderService = null,
        ?JsonWebKeySetService $jsonWebKeySetService = null,
        ?OpMetadataService $opMetadataService = null,
        ?ClientRepository $clientRepository = null,
        ?Helpers $helpers = null,
        ?Routes $routes = null,
        ?Federation $federation = null,
        ?LoggerService $loggerService = null,
        ?FederationCache $federationCache = null,
    ): EntityStatementController {
        $moduleConfig ??= $this->moduleConfigMock;
        $jsonWebTokenBuilderService ??= $this->jsonWebTokenBuilderServiceMock;
        $jsonWebKeySetService ??= $this->jsonWebKeySetServiceMock;
        $opMetadataService ??= $this->opMetadataServiceMock;
        $clientRepository ??= $this->clientRepositoryMock;
        $helpers ??= $this->helpersMock;
        $routes ??= $this->routesMock;
        $federation ??= $this->federationMock;
        $loggerService ??= $this->loggerServiceMock;
        $federationCache ??= $this->federationCacheMock;

        return new EntityStatementController(
            $moduleConfig,
            $jsonWebTokenBuilderService,
            $jsonWebKeySetService,
            $opMetadataService,
            $clientRepository,
            $helpers,
            $routes,
            $federation,
            $loggerService,
            $federationCache,
        );
    }

    public function testCanCreateInstance(): void
    {
        $this->moduleConfigMock->expects($this->once())->method('getFederationEnabled')->willReturn(true);
        $this->assertInstanceOf(EntityStatementController::class, $this->sut());
    }

    public function testThrowsIfFederationNotEnabled(): void
    {
        $this->moduleConfigMock->expects($this->once())->method('getFederationEnabled')->willReturn(false);
        $this->expectException(OidcServerException::class);
        $this->expectExceptionMessage('refused');

        $this->sut();
    }

    public function testCanGetConfigurationStatement(): void
    {
        $this->moduleConfigMock->expects($this->once())->method('getFederationEnabled')->willReturn(true);
        $this->federationCacheMock->expects($this->once())->method('get')->willReturn(null);

        // TODO v7 mivanci
        $this->markTestIncomplete('Move to simplesamlphp/openid library for building entity statements.');
    }
}
