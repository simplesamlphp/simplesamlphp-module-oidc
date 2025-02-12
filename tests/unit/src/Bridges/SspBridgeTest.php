<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Bridges;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Bridges\SspBridge;

#[CoversClass(SspBridge::class)]
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
        $this->assertInstanceOf(SspBridge\Utils::class, $this->sut()->utils());
    }

    public function testCanBuildModuleInstance(): void
    {
        $this->assertInstanceOf(SspBridge\Module::class, $this->sut()->module());
    }

    public function testCanBuildAuthInstance(): void
    {
        $this->assertInstanceOf(SspBridge\Auth::class, $this->sut()->auth());
    }
}
