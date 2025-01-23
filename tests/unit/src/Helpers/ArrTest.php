<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Helpers;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Helpers\Arr;

#[CoversClass(Arr::class)]
class ArrTest extends TestCase
{
    protected function sut(): Arr
    {
        return new Arr();
    }

    public function testEnsureStringValues(): void
    {
        $this->assertSame(
            ['1', '2'],
            $this->sut()->ensureStringValues([1, 2]),
        );
    }

    public function testIsValueOneOf(): void
    {
        $this->assertTrue($this->sut()->isValueOneOf('a', ['a']));
        $this->assertTrue($this->sut()->isValueOneOf(['a'], ['a']));
        $this->assertTrue($this->sut()->isValueOneOf(['a', 'b'], ['a']));

        $this->assertFalse($this->sut()->isValueOneOf('a', ['b']));
        $this->assertFalse($this->sut()->isValueOneOf(['a'], ['b']));
    }

    public function testIsValueSubsetOf(): void
    {
        $this->assertTrue($this->sut()->isValueSubsetOf('a', ['a', 'b', 'c']));
        $this->assertTrue($this->sut()->isValueSubsetOf(['a'], ['a', 'b', 'c']));
        $this->assertTrue($this->sut()->isValueSubsetOf(['a', 'b'], ['a', 'b', 'c']));

        $this->assertFalse($this->sut()->isValueSubsetOf('a', []));
        $this->assertFalse($this->sut()->isValueSubsetOf('a', ['b']));
        $this->assertFalse($this->sut()->isValueSubsetOf(['a', 'c'], ['b']));
    }

    public function testIsValueSupersetOf(): void
    {
        $this->assertTrue($this->sut()->isValueSupersetOf('a', ['a']));
        $this->assertTrue($this->sut()->isValueSupersetOf(['a'], ['a']));
        $this->assertTrue($this->sut()->isValueSupersetOf(['a', 'b'], ['a']));

        $this->assertFalse($this->sut()->isValueSupersetOf('a', ['b']));
        $this->assertFalse($this->sut()->isValueSupersetOf(['a'], ['b']));
    }
}
