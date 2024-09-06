<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Helpers;

class Str
{
    /**
     * Converts a scopes query string to an array to easily iterate for validation.
     *
     * @return string[]
     */
    public function convertScopesStringToArray(string $scopes, string $delimiter = ' '): array
    {
        return array_filter(explode($delimiter, trim($scopes)), fn($scope) => !empty($scope));
    }
}
