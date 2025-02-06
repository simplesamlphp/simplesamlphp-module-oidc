<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Bridges\SspBridge\Auth;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Bridges\SspBridge\Auth\Source;

#[CoversClass(Source::class)]
class SourceTest extends TestCase
{
    protected function sut(): Source
    {
        return new Source();
    }

    public function testCanGetSources(): void
    {
        $this->assertTrue(in_array('admin', $this->sut()->getSources()));
    }
}
