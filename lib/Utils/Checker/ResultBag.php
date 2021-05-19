<?php

namespace SimpleSAML\Modules\OpenIDConnect\Utils\Checker;

use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\ResultInterface;

class ResultBag implements ResultBagInterface
{
    /**
     * @var ResultInterface[] $results
     */
    protected $results = [];

    /**
     * @param ResultInterface $result
     */
    public function add(ResultInterface $result): void
    {
        $this->results[$result->getKey()] = $result->getValue();
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
            throw new \LogicException(\sprintf('Checker error: expected result not found (%s)', $key));
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
