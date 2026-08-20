<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

/**
 * Guards the message catalogs against drift from the code.
 *
 * Every string marked for translation has to exist as a msgid in each catalog, otherwise translators
 * never see it and no locale can ever translate it. Nothing about this is visible at runtime: gettext
 * falls back to the original string, so a string missing from the catalogs renders exactly like one
 * present but untranslated. That is why they fell behind twice before this test existed.
 *
 * The check runs in one direction only: a used string must be present. It deliberately does not
 * require that every msgid is still used, because a translatable string can reach the templates by
 * routes this file does not parse, and deleting a msgid which is in fact live silently drops the
 * translation and reverts that label to English. Retiring a msgid stays a manual decision.
 *
 * When this fails for a string you just added, add it to every catalog under `locales/`, with an
 * empty msgstr, wrapped the way gettext wraps -- lines of at most 78 columns including the quotes,
 * keeping on each line but the last the space which joins it to the next.
 */
#[CoversNothing]
class TranslationCatalogCoverageTest extends TestCase
{
    protected static string $projectRoot;

    public static function setUpBeforeClass(): void
    {
        self::$projectRoot = dirname(__DIR__, 3);
    }

    /**
     * Every string the code marks for translation must be in every catalog.
     */
    public function testEveryTranslatableStringIsInEveryCatalog(): void
    {
        $used = $this->translatableStrings();
        $this->assertNotEmpty($used, 'Extracted no translatable strings at all, so this test proves nothing.');

        foreach ($this->catalogPaths() as $catalogPath) {
            $missing = array_values(array_diff($used, $this->msgIdsIn($catalogPath)));

            $this->assertSame(
                [],
                $missing,
                sprintf(
                    "%s is missing %d translatable string(s), the first few being:\n  %s",
                    substr($catalogPath, strlen(self::$projectRoot) + 1),
                    count($missing),
                    implode("\n  ", array_slice($missing, 0, 10)),
                ),
            );
        }
    }

    /**
     * A translatable string must not carry leading or trailing whitespace.
     *
     * `'Edit Client '|trans` is the reason this is checked: the space belonged to the sentence being
     * built around the value, not to the string being translated, so the lookup key differed from the
     * catalog entry by one character and the Croatian and Dutch translations of it were never used.
     * Nothing showed, because the fallback is the original string. Concatenate the separator outside
     * the translated literal instead.
     */
    public function testNoTranslatableStringCarriesEdgeWhitespace(): void
    {
        $offenders = array_values(
            array_filter(
                $this->translatableStrings(),
                static fn(string $value): bool => $value !== trim($value),
            ),
        );

        $this->assertSame(
            [],
            array_map(static fn(string $value): string => sprintf('"%s"', $value), $offenders),
            'Translatable strings must not begin or end with whitespace.',
        );
    }

    /**
     * `Translate::noop()` exists to put a literal in front of the extractor. An argument it can not
     * resolve is a string which can never reach a catalog.
     */
    public function testEveryNoopArgumentIsALiteral(): void
    {
        $unresolvable = [];

        foreach ($this->phpSources() as $path) {
            foreach ($this->noopArguments($path) as $argument) {
                if ($argument === null) {
                    $unresolvable[] = substr($path, strlen(self::$projectRoot) + 1);
                }
            }
        }

        $this->assertSame([], array_values(array_unique($unresolvable)));
    }

    /**
     * @return string[]
     */
    protected function translatableStrings(): array
    {
        $strings = [];

        foreach ($this->phpSources() as $path) {
            foreach ($this->noopArguments($path) as $argument) {
                if (is_string($argument) && $argument !== '') {
                    $strings[] = $argument;
                }
            }
        }

        foreach ($this->filesUnder('templates', 'twig') as $path) {
            foreach ($this->twigStrings($path) as $string) {
                if ($string !== '') {
                    $strings[] = $string;
                }
            }
        }

        $strings = array_values(array_unique($strings));
        sort($strings, SORT_NATURAL | SORT_FLAG_CASE);

        return $strings;
    }

    /**
     * @return string[]
     */
    protected function catalogPaths(): array
    {
        $paths = glob(self::$projectRoot . '/locales/*/LC_MESSAGES/oidc.po') ?: [];
        $this->assertNotEmpty($paths, 'Found no message catalogs.');

        return $paths;
    }

    /**
     * Every PHP file which can mark a string for translation.
     *
     * `hooks/` counts as much as `src/` does: the admin menu entry and the federation page links are
     * declared there, and scanning only `src/` let those labels sit outside the catalogs unnoticed.
     *
     * @return string[]
     */
    protected function phpSources(): array
    {
        return array_merge($this->filesUnder('src', 'php'), $this->filesUnder('hooks', 'php'));
    }

    /**
     * @return string[]
     */
    protected function filesUnder(string $directory, string $extension): array
    {
        $found = [];
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator(self::$projectRoot . '/' . $directory),
        );

        /** @var \SplFileInfo $file */
        foreach ($iterator as $file) {
            if ($file->isFile() && $file->getExtension() === $extension) {
                $found[] = $file->getPathname();
            }
        }

        sort($found);

        return $found;
    }

    /**
     * Every `Translate::noop()` argument in a PHP file, as PHP itself would resolve it. Concatenated
     * string literals resolve to the joined value; anything else yields null, meaning unresolvable.
     *
     * @return array<int,string|null>
     */
    protected function noopArguments(string $path): array
    {
        $tokens = array_values(
            array_filter(
                token_get_all((string)file_get_contents($path)),
                static fn(mixed $token): bool => !is_array($token) ||
                    !in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true),
            ),
        );

        $arguments = [];
        $tokenCount = count($tokens);

        for ($i = 0; $i < $tokenCount; $i++) {
            if (
                !is_array($tokens[$i]) || $tokens[$i][0] !== T_STRING || $tokens[$i][1] !== 'Translate' ||
                !isset($tokens[$i + 3]) ||
                !is_array($tokens[$i + 1]) || $tokens[$i + 1][0] !== T_DOUBLE_COLON ||
                !is_array($tokens[$i + 2]) || $tokens[$i + 2][1] !== 'noop' ||
                $tokens[$i + 3] !== '('
            ) {
                continue;
            }

            $value = '';
            $isResolvable = true;

            for ($j = $i + 4; $j < $tokenCount; $j++) {
                $token = $tokens[$j];

                if ($token === ')') {
                    break;
                }

                if ($token === '.' || $token === ',') {
                    continue;
                }

                if (is_array($token) && $token[0] === T_CONSTANT_ENCAPSED_STRING) {
                    $quote = $token[1][0];
                    $inner = substr($token[1], 1, -1);
                    $value .= $quote === "'" ?
                    str_replace(["\\'", '\\\\'], ["'", '\\'], $inner) :
                    stripcslashes($inner);

                    continue;
                }

                $isResolvable = false;
                break;
            }

            $arguments[] = $isResolvable ? $value : null;
        }

        return $arguments;
    }

    /**
     * The three ways a Twig template in this module marks a string for translation.
     *
     * @return string[]
     */
    protected function twigStrings(string $path): array
    {
        $contents = (string)file_get_contents($path);
        $strings = [];

        if (preg_match_all("/'((?:[^'\\\\]|\\\\.)*)'\s*\|\s*trans/", $contents, $matches)) {
            foreach ($matches[1] as $match) {
                $strings[] = str_replace(["\\'", '\\\\'], ["'", '\\'], $match);
            }
        }

        if (preg_match_all('/"((?:[^"\\\\]|\\\\.)*)"\s*\|\s*trans/', $contents, $matches)) {
            foreach ($matches[1] as $match) {
                $strings[] = stripcslashes($match);
            }
        }

        if (preg_match_all('/{%\s*trans\s*%}(.*?){%\s*endtrans\s*%}/s', $contents, $matches)) {
            foreach ($matches[1] as $match) {
                $strings[] = trim($match);
            }
        }

        return array_merge($strings, $this->parenthesisedTransStrings($contents));
    }

    /**
     * Literals inside a parenthesised expression which is then piped to `trans`.
     *
     * `(actionText|default('Submit'))|trans` and `(client.isConfidential ? 'Confidential' : 'Public')|trans`
     * both translate a literal which is not itself directly in front of the filter, so the patterns
     * above miss them. Everything quoted inside the parentheses is collected, which can pick up a
     * literal that is not really translated; that is the safe direction to err in, since a msgid
     * nothing uses is inert while a used string missing from the catalogs is the bug being guarded
     * against.
     *
     * @return string[]
     */
    protected function parenthesisedTransStrings(string $contents): array
    {
        if (!preg_match_all('/\)\s*\|\s*trans/', $contents, $matches, PREG_OFFSET_CAPTURE)) {
            return [];
        }

        $strings = [];

        foreach ($matches[0] as $match) {
            $closingIndex = (int)$match[1];
            $depth = 0;
            $openingIndex = null;

            for ($i = $closingIndex; $i >= 0; $i--) {
                if ($contents[$i] === ')') {
                    $depth++;
                } elseif ($contents[$i] === '(') {
                    $depth--;

                    if ($depth === 0) {
                        $openingIndex = $i;
                        break;
                    }
                }
            }

            if ($openingIndex === null) {
                continue;
            }

            $inner = substr($contents, $openingIndex + 1, $closingIndex - $openingIndex - 1);

            if (preg_match_all("/'((?:[^'\\\\]|\\\\.)*)'/", $inner, $literals)) {
                foreach ($literals[1] as $literal) {
                    $strings[] = str_replace(["\\'", '\\\\'], ["'", '\\'], $literal);
                }
            }
        }

        return $strings;
    }

    /**
     * Catalog msgids, joining the continuation lines of a wrapped entry back together.
     *
     * @return string[]
     */
    protected function msgIdsIn(string $path): array
    {
        $lines = file($path, FILE_IGNORE_NEW_LINES) ?: [];
        $msgIds = [];
        $current = null;

        foreach ($lines as $line) {
            if (str_starts_with($line, 'msgid ')) {
                $current = stripcslashes(substr(trim(substr($line, 6)), 1, -1));

                continue;
            }

            if (!is_null($current) && str_starts_with($line, '"')) {
                $current .= stripcslashes(substr(trim($line), 1, -1));

                continue;
            }

            if (!is_null($current)) {
                $msgIds[] = $current;
                $current = null;
            }
        }

        if (!is_null($current)) {
            $msgIds[] = $current;
        }

        return array_values(array_filter($msgIds, static fn(string $id): bool => $id !== ''));
    }
}
