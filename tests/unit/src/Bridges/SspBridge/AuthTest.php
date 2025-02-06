<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Bridges\SspBridge;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Bridges\SspBridge\Auth;

#[CoversClass(Auth::class)]
class AuthTest extends TestCase
{
    protected function sut(): Auth
    {
        return new Auth();
    }

    public function testCanConstruct(): void
    {
        $this->assertInstanceOf(Auth::class, $this->sut());
    }

    public function testCanBuildSourceInstance(): void
    {
        $this->assertInstanceOf(Auth\Source::class, $this->sut()->source());
    }
}
