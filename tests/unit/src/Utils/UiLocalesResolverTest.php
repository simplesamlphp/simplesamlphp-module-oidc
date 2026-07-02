<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Utils;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Utils\UiLocalesResolver;

#[CoversClass(UiLocalesResolver::class)]
class UiLocalesResolverTest extends TestCase
{
    protected function sut(?array $availableLanguages = null): UiLocalesResolver
    {
        $sspConfiguration = Configuration::loadFromArray(
            $availableLanguages === null ? [] : ['language.available' => $availableLanguages],
        );

        return new UiLocalesResolver($sspConfiguration);
    }

    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(UiLocalesResolver::class, $this->sut());
    }

    public static function uiLocalesProvider(): array
    {
        return [
            'null ui_locales' => [null, ['en', 'hr'], null],
            'empty ui_locales' => ['', ['en', 'hr'], null],
            'blank ui_locales' => ['   ', ['en', 'hr'], null],
            'exact match' => ['hr', ['en', 'hr'], 'hr'],
            'preference order is honored' => ['hr en', ['en', 'hr'], 'hr'],
            'first unavailable, second available' => ['fr en', ['en', 'hr'], 'en'],
            'primary subtag fallback' => ['fr-CA', ['en', 'fr'], 'fr'],
            'case-insensitive match' => ['HR', ['en', 'hr'], 'hr'],
            'separator normalization' => ['pt-BR', ['en', 'pt_BR'], 'pt_BR'],
            'case and separator normalization' => ['PT-br', ['en', 'pt_BR'], 'pt_BR'],
            'no match' => ['de fr', ['en', 'hr'], null],
            'multiple whitespace between tags' => ['de  en', ['en', 'hr'], 'en'],
            'returns configured code, not requested tag' => ['en-US', ['en'], 'en'],
        ];
    }

    #[DataProvider('uiLocalesProvider')]
    public function testCanResolveUiLocales(
        ?string $uiLocales,
        array $availableLanguages,
        ?string $expectedLanguage,
    ): void {
        $this->assertSame($expectedLanguage, $this->sut($availableLanguages)->resolve($uiLocales));
    }

    public function testFallsBackToDefaultAvailableLanguage(): void
    {
        // When language.available is not configured, the SSP fallback language (en) is used.
        $this->assertSame('en', $this->sut()->resolve('en de'));
        $this->assertNull($this->sut()->resolve('de'));
    }
}
