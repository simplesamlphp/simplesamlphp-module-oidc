<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Helpers;

class Arr
{
    /**
     * Find item in array using the given callable.
     *
     * @return mixed|null
     */
    public function findByCallback(array $arr, callable $fn): mixed
    {
        /** @psalm-suppress MixedAssignment */
        foreach ($arr as $x) {
            if (call_user_func($fn, $x) === true) {
                return $x;
            }
        }

        return null;
    }

    /**
     * @param array $values
     * @return string[]
     */
    public function ensureStringValues(array $values): array
    {
        return array_map(fn(mixed $value): string => (string)$value, $values);
    }

    public function isValueOneOf(mixed $value, array $set): bool
    {
        $value = is_array($value) ? $value : [$value];
        return !empty(array_intersect($value, $set));
    }

    public function isValueSubsetOf(mixed $value, array $superset): bool
    {
        $value = is_array($value) ? $value : [$value];

        return empty(array_diff($value, $superset));
    }

    public function isValueSupersetOf(mixed $value, array $subset): bool
    {
        $value = is_array($value) ? $value : [$value];

        // Opposite of subset...
        return $this->isValueSubsetOf($subset, $value);
    }
}
