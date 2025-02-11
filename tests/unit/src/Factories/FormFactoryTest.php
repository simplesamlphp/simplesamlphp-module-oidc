<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Factories;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Factories\FormFactory;
use SimpleSAML\Module\oidc\Forms\ClientForm;
use SimpleSAML\Module\oidc\Forms\Controls\CsrfProtection;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;

#[CoversClass(FormFactory::class)]
#[UsesClass(ClientForm::class)]
class FormFactoryTest extends TestCase
{
    protected MockObject $moduleConfigMock;
    protected MockObject $csrfProtectionMock;
    protected MockObject $sspBridgeMock;
    protected MockObject $helpersMock;

    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->csrfProtectionMock = $this->createMock(CsrfProtection::class);
        $this->sspBridgeMock = $this->createMock(SspBridge::class);
        $this->helpersMock = $this->createMock(Helpers::class);
    }

    protected function sut(
        ?ModuleConfig $moduleConfig = null,
        ?CsrfProtection $csrfProtection = null,
        ?SspBridge $sspBridge = null,
        ?Helpers $helpers = null,
    ): FormFactory {
        $moduleConfig ??= $this->moduleConfigMock;
        $csrfProtection ??= $this->csrfProtectionMock;
        $sspBridge ??= $this->sspBridgeMock;
        $helpers ??= $this->helpersMock;

        return new FormFactory(
            $moduleConfig,
            $csrfProtection,
            $sspBridge,
            $helpers,
        );
    }

    public function testCanConstruct(): void
    {
        $this->assertInstanceOf(FormFactory::class, $this->sut());
    }

    public function testCanBuildClientForm(): void
    {
        $this->assertInstanceOf(
            ClientForm::class,
            $this->sut()->build(ClientForm::class),
        );
    }
}
