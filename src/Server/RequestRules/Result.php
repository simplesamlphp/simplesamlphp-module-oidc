<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules;

/**
 * Result of a single request rule check.
 *
 * The generic parameter T describes the type of the contained value. Each rule binds it via
 * its `@extends AbstractRule<...>` annotation, which in turn lets the ResultBag infer the value
 * type when a result is fetched by its rule class-string.
 *
 * @template-covariant T
 */
class Result
{
    /**
     * @param T $value
     */
    public function __construct(protected string $key, protected mixed $value = null)
    {
    }

    public function getKey(): string
    {
        return $this->key;
    }

    /**
     * @return T
     */
    public function getValue(): mixed
    {
        return $this->value;
    }
}
