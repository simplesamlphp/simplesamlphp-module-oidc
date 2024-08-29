<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\RequestRuleInterface;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;

abstract class AbstractRule implements RequestRuleInterface
{
    public function __construct(protected RequestParamsResolver $requestParamsResolver)
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
