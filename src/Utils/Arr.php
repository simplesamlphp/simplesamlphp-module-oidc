<?php

namespace SimpleSAML\Module\oidc\Utils;

/**
 * Helper for arrays.
 *
 * Class Arr
 * @package SimpleSAML\Module\oidc\Utils
 */
class Arr
{
    /**
     * Find item in array using the given callable.
     *
     * @param array $arr
     * @param callable $fn
     * @return mixed|null
     */
    public static function find(array $arr, callable $fn)
    {
        foreach ($arr as $x) {
            if (call_user_func($fn, $x) === true) {
                return $x;
            }
        }

        return null;
    }
}
