<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\RequestRuleInterface;
use SimpleSAML\Module\oidc\Utils\ParamsResolver;

abstract class AbstractRule implements RequestRuleInterface
{
    public function __construct(protected ParamsResolver $paramsResolver)
    {
    }

    /**
     * @inheritDoc
     */
    public function getKey(): string
    {
        return static::class;
    }
}
