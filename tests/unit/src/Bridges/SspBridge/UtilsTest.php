<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Bridges\SspBridge;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Bridges\SspBridge\Utils;
use SimpleSAML\Utils\Auth;
use SimpleSAML\Utils\Config;
use SimpleSAML\Utils\HTTP;
use SimpleSAML\Utils\Random;

#[CoversClass(Utils::class)]
class UtilsTest extends TestCase
{
    protected function sut(): Utils
    {
        return new Utils();
    }

    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(Utils::class, $this->sut());
    }

    public function testCanBuildConfigInstance(): void
    {
        $this->assertInstanceOf(Config::class, $this->sut()->config());
    }

    public function testCanBuildHttpInstance(): void
    {
        $this->assertInstanceOf(HTTP::class, $this->sut()->http());
    }

    public function testCanBuildRandomInstance(): void
    {
        $this->assertInstanceOf(Random::class, $this->sut()->random());
    }

    public function testCanBuildAuthInstance(): void
    {
        $this->assertInstanceOf(Auth::class, $this->sut()->auth());
    }
}
