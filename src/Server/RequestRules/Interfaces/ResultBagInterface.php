<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Interfaces;

use SimpleSAML\Module\oidc\Server\RequestRules\Result;

interface ResultBagInterface
{
    /**
     * Add result to the result bag.
     *
     * @param \SimpleSAML\Module\oidc\Server\RequestRules\Result<mixed> $result
     */
    public function add(Result $result): void;

    /**
     * Get specific result or null if it doesn't exist.
     *
     * The value type is inferred from the rule class-string passed as the key.
     *
     * @template T
     * @param class-string<RequestRuleInterface<T>> $key
     * @return \SimpleSAML\Module\oidc\Server\RequestRules\Result<T>|null
     */
    public function get(string $key): ?Result;

    /**
     * Get specific result or fail if it doesn't exist.
     *
     * The value type is inferred from the rule class-string passed as the key.
     *
     * @template T
     * @param class-string<RequestRuleInterface<T>> $key
     * @return \SimpleSAML\Module\oidc\Server\RequestRules\Result<T>
     * @throws \Throwable If result with specific key is not present.
     */
    public function getOrFail(string $key): Result;

    /**
     * Get the value of a specific result or fail if the result doesn't exist.
     *
     * Convenience accessor that skips the intermediate Result object. The value type is inferred
     * from the rule class-string passed as the key.
     *
     * @template T
     * @param class-string<RequestRuleInterface<T>> $key
     * @return T
     * @throws \Throwable If result with specific key is not present.
     */
    public function getValueOrFail(string $key): mixed;

    /**
     * Get all results.
     * @return array<string, \SimpleSAML\Module\oidc\Server\RequestRules\Result<mixed>>
     */
    public function getAll(): array;

    /**
     * Remove result from the result bag.
     */
    public function remove(string $key): void;

    /**
     * Check if specific result exists in result bag.
     */
    public function has(string $key): bool;
}
