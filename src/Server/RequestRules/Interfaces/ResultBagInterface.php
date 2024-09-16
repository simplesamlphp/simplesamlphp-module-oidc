<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Interfaces;

interface ResultBagInterface
{
    /**
     * Add result to the result bag.
     */
    public function add(ResultInterface $result): void;

    /**
     * Get specific result or null if it doesn't exist.
     */
    public function get(string $key): ?ResultInterface;

    /**
     * Get specific result or fail if it doesn't exits.
     * @throws \Throwable If result with specific key is not present.
     */
    public function getOrFail(string $key): ResultInterface;

    /**
     * Get all results.
     * @return \SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface[]
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
