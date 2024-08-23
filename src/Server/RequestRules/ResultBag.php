<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules;

use LogicException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;

use function sprintf;

class ResultBag implements ResultBagInterface
{
    /**
     * @var \SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface[] $results
     */
    protected array $results = [];

    /**
     * @param \SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface $result
     */
    public function add(ResultInterface $result): void
    {
        $this->results[$result->getKey()] = $result;
    }

    /**
     * @param string $key
     * @return \SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface|null
     */
    public function get(string $key): ?ResultInterface
    {
        return $this->results[$key] ?? null;
    }

    /**
     * @param string $key
     * @return \SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface
     */
    public function getOrFail(string $key): ResultInterface
    {
        $result = $this->get($key);

        if ($result === null) {
            throw new LogicException(sprintf('Checker error: expected existing result, but none found (%s)', $key));
        }

        return $result;
    }

    /**
     * @return \SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface[]
     */
    public function getAll(): array
    {
        return $this->results;
    }

    /**
     * @param string $key
     */
    public function remove(string $key): void
    {
        unset($this->results[$key]);
    }
}
