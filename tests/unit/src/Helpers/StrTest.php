<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Helpers;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Helpers\Str;

#[CoversClass(Str::class)]
class StrTest extends TestCase
{
    protected function sut(): Str
    {
        return new Str();
    }

    public function testCanConvertScopesStringToArray(): void
    {
        $this->assertSame(
            ['a', 'b'],
            $this->sut()->convertScopesStringToArray('a b'),
        );
    }

    public function testCanConvertTextToArray(): void
    {
        $this->assertSame(
            ['a', 'b', 'c', 'd'],
            $this->sut()->convertTextToArray("a\tb\nc\rd"),
        );
    }
}
