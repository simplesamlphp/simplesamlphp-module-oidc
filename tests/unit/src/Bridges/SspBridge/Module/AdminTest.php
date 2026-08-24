<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Bridges\SspBridge\Module;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\admin\Controller\Menu;
use SimpleSAML\Module\oidc\Bridges\SspBridge\Module\Admin;

#[CoversClass(Admin::class)]
#[AllowMockObjectsWithoutExpectations]
class AdminTest extends TestCase
{
    protected function sut(): Admin
    {
        return new Admin();
    }


    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(Admin::class, $this->sut());
    }


    public function testCanBuildSspAdminMenu(): void
    {
        $this->assertInstanceOf(Menu::class, $this->sut()->buildSspAdminMenu());
    }
}
