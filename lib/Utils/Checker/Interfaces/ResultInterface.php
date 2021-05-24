<?php

namespace SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces;

interface ResultInterface
{
    /**
     * Get result key.
     * @return string
     */
    public function getKey(): string;

    /**
     * Get result value.
     * @return mixed
     */
    public function getValue();

    /**
     * Set (new) value.
     * @param mixed $value
     */
    public function setValue($value): void;
}
