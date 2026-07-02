<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Bridges\SspBridge\Locale;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Bridges\SspBridge\Locale\Language;

#[CoversClass(Language::class)]
class LanguageTest extends TestCase
{
    protected function sut(): Language
    {
        return new Language();
    }

    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(Language::class, $this->sut());
    }
}
