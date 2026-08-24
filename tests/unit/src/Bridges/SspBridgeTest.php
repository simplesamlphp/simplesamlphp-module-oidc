<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Bridges;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Bridges\SspBridge\Auth;
use SimpleSAML\Module\oidc\Bridges\SspBridge\Locale;
use SimpleSAML\Module\oidc\Bridges\SspBridge\Module;
use SimpleSAML\Module\oidc\Bridges\SspBridge\Utils;

#[CoversClass(SspBridge::class)]
#[AllowMockObjectsWithoutExpectations]
class SspBridgeTest extends TestCase
{
    protected function sut(): SspBridge
    {
        return new SspBridge();
    }


    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(SspBridge::class, $this->sut());
    }


    public function testCanBuildUtilsInstance(): void
    {
        $this->assertInstanceOf(Utils::class, $this->sut()->utils());
    }


    public function testCanBuildModuleInstance(): void
    {
        $this->assertInstanceOf(Module::class, $this->sut()->module());
    }


    public function testCanBuildAuthInstance(): void
    {
        $this->assertInstanceOf(Auth::class, $this->sut()->auth());
    }


    public function testCanBuildLocaleInstance(): void
    {
        $this->assertInstanceOf(Locale::class, $this->sut()->locale());
    }
}
