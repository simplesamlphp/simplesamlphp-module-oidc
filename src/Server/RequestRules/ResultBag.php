<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules;

use LogicException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;

use function sprintf;

class ResultBag implements ResultBagInterface
{
    /**
     * @var array<string, \SimpleSAML\Module\oidc\Server\RequestRules\Result<mixed>> $results
     */
    protected array $results = [];

    public function add(Result $result): void
    {
        $this->results[$result->getKey()] = $result;
    }

    /**
     * @template T
     * @param class-string<\SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\RequestRuleInterface<T>> $key
     * @return \SimpleSAML\Module\oidc\Server\RequestRules\Result<T>|null
     */
    public function get(string $key): ?Result
    {
        /** @var \SimpleSAML\Module\oidc\Server\RequestRules\Result<T>|null */
        return $this->results[$key] ?? null;
    }

    /**
     * @template T
     * @param class-string<\SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\RequestRuleInterface<T>> $key
     * @return \SimpleSAML\Module\oidc\Server\RequestRules\Result<T>
     */
    public function getOrFail(string $key): Result
    {
        $result = $this->get($key);

        if ($result === null) {
            throw new LogicException(
                sprintf('Request rule error: expected existing result, but none found (%s)', $key),
            );
        }

        return $result;
    }

    /**
     * @template T
     * @param class-string<\SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\RequestRuleInterface<T>> $key
     * @return T
     */
    public function getValueOrFail(string $key): mixed
    {
        return $this->getOrFail($key)->getValue();
    }

    /**
     * @return array<string, \SimpleSAML\Module\oidc\Server\RequestRules\Result<mixed>>
     */
    public function getAll(): array
    {
        return $this->results;
    }

    public function remove(string $key): void
    {
        unset($this->results[$key]);
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->results);
    }
}
