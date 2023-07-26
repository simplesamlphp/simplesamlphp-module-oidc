<?php

namespace SimpleSAML\Test\Module\oidc\Controller;

use Laminas\Diactoros\Response\RedirectResponse;
use Laminas\Diactoros\ServerRequest;
use SimpleSAML\Module\oidc\Controller\OpenIdConnectInstallerController;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Services\DatabaseLegacyOAuth2Import;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;
use SimpleSAML\Module\oidc\Services\SessionMessagesService;
use SimpleSAML\XHTML\Template;

/**
 * @covers \SimpleSAML\Module\oidc\Controller\OpenIdConnectInstallerController
 */
class OpenIdConnectInstallerControllerTest extends TestCase
{
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $templateFactoryMock;
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $sessionMessagesService;
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $databaseMigrationMock;
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $databaseLegacyOAuth2ImportMock;
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $serverRequestMock;
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $templateMock;

    protected function setUp(): void
    {
        $this->templateFactoryMock = $this->createMock(TemplateFactory::class);
        $this->sessionMessagesService = $this->createMock(SessionMessagesService::class);
        $this->databaseMigrationMock = $this->createMock(DatabaseMigration::class);
        $this->databaseLegacyOAuth2ImportMock = $this->createMock(DatabaseLegacyOAuth2Import::class);

        $this->serverRequestMock = $this->createMock(ServerRequest::class);
        $this->templateMock = $this->createMock(Template::class);
    }

    protected function createStubbedInstance(): OpenIdConnectInstallerController
    {
        return new OpenIdConnectInstallerController(
            $this->templateFactoryMock,
            $this->sessionMessagesService,
            $this->databaseMigrationMock,
            $this->databaseLegacyOAuth2ImportMock
        );
    }

    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            OpenIdConnectInstallerController::class,
            $this->createStubbedInstance()
        );
    }

    public function testItReturnsToMainPageIfAlreadyUpdated(): void
    {
        $this->databaseMigrationMock
            ->expects($this->once())
            ->method('isUpdated')
            ->willReturn(true);

        $this->assertInstanceOf(
            RedirectResponse::class,
            $this->createStubbedInstance()->__invoke($this->serverRequestMock)
        );
    }

    public function testItShowsInformationPage(): void
    {
        $this->serverRequestMock->expects($this->once())->method('getParsedBody');
        $this->serverRequestMock->expects($this->once())->method('getMethod')->willReturn('GET');
        $this->templateFactoryMock
            ->expects($this->once())
            ->method('render')
            ->with('oidc:install.twig', ['oauth2_enabled' => false,])
            ->willReturn($this->templateMock);

        $this->assertSame(
            $this->templateMock,
            $this->createStubbedInstance()->__invoke($this->serverRequestMock)
        );
    }

    public function testItRequiresConfirmationBeforeInstallSchema(): void
    {
        $this->serverRequestMock->expects($this->once())->method('getParsedBody');
        $this->serverRequestMock->expects($this->once())->method('getMethod')->willReturn('POST');
        $this->databaseMigrationMock->expects($this->never())->method('migrate');
        $this->templateFactoryMock
            ->expects($this->once())
            ->method('render')
            ->with('oidc:install.twig', ['oauth2_enabled' => false,])
            ->willReturn($this->templateMock);

        $this->assertSame(
            $this->templateMock,
            $this->createStubbedInstance()->__invoke($this->serverRequestMock)
        );
    }

    public function testItCreatesSchema(): void
    {
        $this->serverRequestMock->expects($this->once())->method('getParsedBody')->willReturn(['migrate' => true,]);
        $this->serverRequestMock->expects($this->once())->method('getMethod')->willReturn('POST');
        $this->databaseMigrationMock->expects($this->once())->method('migrate');
        $this->databaseLegacyOAuth2ImportMock->expects($this->never())->method('import');
        $this->sessionMessagesService->expects($this->once())->method('addMessage')->with('{oidc:install:finished}');

        $this->assertInstanceOf(
            RedirectResponse::class,
            $this->createStubbedInstance()->__invoke($this->serverRequestMock)
        );
    }

    public function testItImportsDataFromOauth2Module(): void
    {
        $this->serverRequestMock
            ->expects($this->once())
            ->method('getParsedBody')
            ->willReturn(['migrate' => true, 'oauth2_migrate' => true,]);
        $this->serverRequestMock->expects($this->once())->method('getMethod')->willReturn('POST');
        $this->databaseMigrationMock->expects($this->once())->method('migrate');
        $this->databaseLegacyOAuth2ImportMock->expects($this->once())->method('import');
        $this->sessionMessagesService
            ->expects($this->atLeast(2))
            ->method('addMessage')
            ->with($this->callback(function ($message) {
                return in_array($message, ['{oidc:install:finished}', '{oidc:import:finished}']);
            }));

        $this->assertInstanceOf(
            RedirectResponse::class,
            $this->createStubbedInstance()->__invoke($this->serverRequestMock)
        );
    }
}
