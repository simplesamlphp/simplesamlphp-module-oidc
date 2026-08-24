<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Bridges\SspBridge;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Bridges\SspBridge\Module;
use SimpleSAML\Module\oidc\Bridges\SspBridge\Module\Admin;

#[CoversClass(Module::class)]
#[AllowMockObjectsWithoutExpectations]
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
        $this->assertInstanceOf(Admin::class, $this->sut()->admin());
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
