<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Bridges\SspBridge;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Bridges\SspBridge\Locale;
use SimpleSAML\Module\oidc\Bridges\SspBridge\Locale\Language;

#[CoversClass(Locale::class)]
#[AllowMockObjectsWithoutExpectations]
class LocaleTest extends TestCase
{
    protected function sut(): Locale
    {
        return new Locale();
    }


    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(Locale::class, $this->sut());
    }


    public function testCanBuildLanguageInstance(): void
    {
        $this->assertInstanceOf(Language::class, $this->sut()->language());
    }
}
