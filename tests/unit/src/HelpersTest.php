<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Helpers;

#[CoversClass(Helpers::class)]
#[UsesClass(Helpers\Http::class)]
#[UsesClass(Helpers\Client::class)]
#[UsesClass(Helpers\DateTime::class)]
#[UsesClass(Helpers\Str::class)]
#[UsesClass(Helpers\Arr::class)]
#[UsesClass(Helpers\Random::class)]
class HelpersTest extends TestCase
{
    protected function sut(): Helpers
    {
        return new Helpers();
    }

    public function testCanBuildHelpers(): void
    {
        $this->assertInstanceOf(Helpers\Http::class, $this->sut()->http());
        $this->assertInstanceOf(Helpers\Client::class, $this->sut()->client());
        $this->assertInstanceOf(Helpers\DateTime::class, $this->sut()->dateTime());
        $this->assertInstanceOf(Helpers\Str::class, $this->sut()->str());
        $this->assertInstanceOf(Helpers\Arr::class, $this->sut()->arr());
        $this->assertInstanceOf(Helpers\Random::class, $this->sut()->random());
    }
}
