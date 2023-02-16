<?php

namespace SimpleSAML\Module\oidc\Utils\Checker\Interfaces;

interface ResultBagInterface
{
    /**
     * Add result to the result bag.
     * @param ResultInterface $result
     */
    public function add(ResultInterface $result): void;

    /**
     * Get specific result or null if it doesn't exist.
     * @param string $key
     * @return ResultInterface|null
     */
    public function get(string $key): ?ResultInterface;

    /**
     * Get specific result or fail if it doesn't exits.
     * @param string $key
     * @return ResultInterface
     * @throws \Throwable If result with specific key is not present.
     */
    public function getOrFail(string $key): ResultInterface;

    /**
     * Get all results.
     * @return ResultInterface[]
     */
    public function getAll(): array;

    /**
     * Remove result from the result bag.
     * @param string $key
     */
    public function remove(string $key): void;
}
