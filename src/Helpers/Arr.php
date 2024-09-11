<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Helpers;

class Arr
{
    /**
     * @param array $values
     * @return string[]
     */
    public function ensureStringValues(array $values): array
    {
        return array_map(fn(mixed $value): string => (string)$value, $values);
    }
}
