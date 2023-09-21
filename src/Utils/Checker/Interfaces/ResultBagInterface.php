<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils\Checker\Interfaces;

use Throwable;

interface ResultBagInterface
{
    /**
     * Add result to the result bag.
     */
    public function add(ResultInterface $result): void;

    /**
     * Get specific result or null if it doesn't exist.
     * @return ResultInterface|null
     */
    public function get(string $key): ?ResultInterface;

    /**
     * Get specific result or fail if it doesn't exits.
     * @return ResultInterface
     * @throws Throwable If result with specific key is not present.
     */
    public function getOrFail(string $key): ResultInterface;

    /**
     * Get all results.
     * @return ResultInterface[]
     */
    public function getAll(): array;

    /**
     * Remove result from the result bag.
     */
    public function remove(string $key): void;
}
