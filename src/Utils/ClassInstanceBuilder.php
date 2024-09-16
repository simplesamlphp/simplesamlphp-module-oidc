<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils;

use ReflectionClass;
use SimpleSAML\Module\oidc\OidcException;

class ClassInstanceBuilder
{
    /**
     * @throws \SimpleSAML\Module\oidc\OidcException
     * @throws \ReflectionException
     */
    public function build(string $class, array $args): mixed
    {
        if (!class_exists($class)) {
            $message = "Error building instance: class {$class} does not exist";
            throw new OidcException($message);
        }

        return (new ReflectionClass($class))->newInstance(...$args);
    }
}
