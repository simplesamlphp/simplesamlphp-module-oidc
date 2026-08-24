<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Helpers\Arr;
use SimpleSAML\Module\oidc\Helpers\Client;
use SimpleSAML\Module\oidc\Helpers\DateTime;
use SimpleSAML\Module\oidc\Helpers\Http;
use SimpleSAML\Module\oidc\Helpers\Random;
use SimpleSAML\Module\oidc\Helpers\Scope;
use SimpleSAML\Module\oidc\Helpers\Str;

#[CoversClass(Helpers::class)]
#[UsesClass(Http::class)]
#[UsesClass(Client::class)]
#[UsesClass(DateTime::class)]
#[UsesClass(Str::class)]
#[UsesClass(Arr::class)]
#[UsesClass(Random::class)]
#[UsesClass(Scope::class)]
#[AllowMockObjectsWithoutExpectations]
class HelpersTest extends TestCase
{
    protected function sut(): Helpers
    {
        return new Helpers();
    }


    public function testCanBuildHelpers(): void
    {
        $this->assertInstanceOf(Http::class, $this->sut()->http());
        $this->assertInstanceOf(Client::class, $this->sut()->client());
        $this->assertInstanceOf(DateTime::class, $this->sut()->dateTime());
        $this->assertInstanceOf(Str::class, $this->sut()->str());
        $this->assertInstanceOf(Arr::class, $this->sut()->arr());
        $this->assertInstanceOf(Random::class, $this->sut()->random());
        $this->assertInstanceOf(Scope::class, $this->sut()->scope());
    }
}
