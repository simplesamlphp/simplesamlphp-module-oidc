<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Factories;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Admin\Menu;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\SessionMessagesService;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\XHTML\Template;

#[CoversClass(TemplateFactory::class)]
#[UsesClass(Template::class)]
#[UsesClass(Configuration::class)]
class TemplateFactoryTest extends TestCase
{
    protected Configuration $sspConfiguration;
    protected MockObject $moduleConfigMock;
    protected MockObject $menuMock;
    protected MockObject $sspBridgeMock;
    protected MockObject $sessionMessagesServiceMock;
    protected MockObject $routes;
    protected MockObject $sspBridgeModuleMock;
    protected MockObject $sspBridgeModuleAdminMock;

    protected function setUp(): void
    {
        // Template instantiation uses a bunch of configuration options from SSP config file, so let's use test
        // config file for that by default instead of mocking it all.
        $this->sspConfiguration = Configuration::getInstance();

        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->menuMock = $this->createMock(Menu::class);
        $this->sspBridgeMock = $this->createMock(SspBridge::class);
        $this->sessionMessagesServiceMock = $this->createMock(SessionMessagesService::class);
        $this->routes = $this->createMock(Routes::class);

        $this->sspBridgeModuleMock = $this->createMock(SspBridge\Module::class);
        $this->sspBridgeMock->method('module')->willReturn($this->sspBridgeModuleMock);
        $this->sspBridgeModuleAdminMock = $this->createMock(SspBridge\Module\Admin::class);
        $this->sspBridgeModuleMock->method('admin')->willReturn($this->sspBridgeModuleAdminMock);
    }

    protected function sut(
        ?Configuration $configuration = null,
        ?ModuleConfig $moduleConfig = null,
        ?Menu $menu = null,
        ?SspBridge $sspBridge = null,
        ?SessionMessagesService $sessionMessagesService = null,
        ?Routes $routes = null,
    ): TemplateFactory {
        $configuration ??= $this->sspConfiguration;
        $moduleConfig ??= $this->moduleConfigMock;
        $menu ??= $this->menuMock;
        $sspBridge ??= $this->sspBridgeMock;
        $sessionMessagesService ??= $this->sessionMessagesServiceMock;
        $routes ??= $this->routes;

        return new TemplateFactory(
            $configuration,
            $moduleConfig,
            $menu,
            $sspBridge,
            $sessionMessagesService,
            $routes,
        );
    }

    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(TemplateFactory::class, $this->sut());
    }

    public function testCanBuildTemplate(): void
    {
        $template = $this->sut()->build('oidc:clients/index.twig', [], 'path');

        $this->assertInstanceOf(Template::class, $template);
    }

    public function testCanAddTemplatesFromAdminModule(): void
    {
        $this->sspBridgeModuleMock->expects($this->once())->method('isModuleEnabled')
            ->with('admin')->willReturn(true);
        $this->sspBridgeModuleAdminMock->expects($this->once())->method('buildSspAdminMenu')
        ->willReturn(new \SimpleSAML\Module\admin\Controller\Menu()); // SSP Admin Menu is final so can't be mocked.

        $this->sut()->build('oidc:clients/index.twig');
    }

    public function testCanSetActiveHrefPath(): void
    {
        $this->menuMock->expects($this->once())->method('setActiveHrefPath');
        $this->menuMock->expects($this->once())->method('getActiveHrefPath');

        $sut = $this->sut();
        $sut->setActiveHrefPath('path');
        $sut->getActiveHrefPath();
    }

    public function testCanSetTemplateFactoryProperties(): void
    {
        $sut = $this->sut();
        $this->assertInstanceOf(TemplateFactory::class, $sut->setShowMenu(true));
        $this->assertInstanceOf(TemplateFactory::class, $sut->setIncludeDefaultMenuItems(true));
    }
}
