<?php

namespace SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Modules\OpenIDConnect\Server\Exceptions\OidcServerException;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\RequestRuleInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\ResultInterface;

abstract class AbstractRule implements RequestRuleInterface
{
    /**
     * @inheritDoc
     */
    public function getKey(): string
    {
        return self::class;
    }
}
