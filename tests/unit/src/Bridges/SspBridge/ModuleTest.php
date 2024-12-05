<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Bridges\SspBridge;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Bridges\SspBridge\Module;

#[CoversClass(Module::class)]
class ModuleTest extends TestCase
{
    protected function sut(): Module
    {
        return new Module();
    }

    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(Module::class, $this->sut());
    }

    public function testCanBuildAdminInstance(): void
    {
        $this->assertInstanceOf(Module\Admin::class, $this->sut()->admin());
    }

    public function testCanGetModuleUrl(): void
    {
        $this->assertStringContainsString(
            'test',
            $this->sut()->getModuleUrl('test'),
        );
    }

    public function testCanCheckIsModuleEnabled(): void
    {
        $this->assertFalse($this->sut()->isModuleEnabled('invalid'));
        $this->assertTrue($this->sut()->isModuleEnabled('core'));
    }
}
