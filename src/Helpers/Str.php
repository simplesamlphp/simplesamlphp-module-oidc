<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Helpers;

class Str
{
    /**
     * Converts a scopes query string to an array to easily iterate for validation.
     *
     * @param non-empty-string $delimiter
     * @return string[]
     */
    public function convertScopesStringToArray(string $scopes, string $delimiter = ' '): array
    {
        return array_filter(explode($delimiter, trim($scopes)), fn($scope) => !empty($scope));
    }

    /**
     * @param non-empty-string $pattern
     * @return string[]
     */
    public function convertTextToArray(string $text, string $pattern = "/[\t\r\n]+/"): array
    {
        return array_filter(
            preg_split($pattern, $text),
            fn(string $line): bool => !empty(trim($line)),
        );
    }
}
