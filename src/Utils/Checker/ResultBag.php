<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils\Checker;

use LogicException;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultInterface;

use function sprintf;

class ResultBag implements ResultBagInterface
{
    /**
     * @var ResultInterface[] $results
     */
    protected array $results = [];

    /**
     * @param ResultInterface $result
     */
    public function add(ResultInterface $result): void
    {
        $this->results[$result->getKey()] = $result;
    }

    /**
     * @param string $key
     * @return ResultInterface|null
     */
    public function get(string $key): ?ResultInterface
    {
        if (isset($this->results[$key])) {
            return $this->results[$key];
        }

        return null;
    }

    /**
     * @param string $key
     * @return ResultInterface
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
     * @return ResultInterface[]
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
