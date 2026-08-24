<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Bridges\SspBridge\Locale;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Bridges\SspBridge\Locale\Language;

#[CoversClass(Language::class)]
#[AllowMockObjectsWithoutExpectations]
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


    public function testCanGetAvailableLanguages(): void
    {
        $configuration = Configuration::loadFromArray([
            'language.available' => ['en', 'hr'],
        ]);

        $this->assertSame(['en', 'hr'], $this->sut()->getAvailableLanguages($configuration));
    }
}
