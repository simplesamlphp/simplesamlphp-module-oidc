<?php

namespace SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Result;

class StateRule implements \SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\RequestRuleInterface
{
    /**
     * @inheritDoc
     */
    public static function getKey(): string
    {
        return 'state';
    }

    /**
     * @inheritDoc
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        array $data
    ): ?ResultInterface {
        /** @var string|null $state */
        $state = $request->getQueryParams()['state'] ?? null;

        return new Result(self::getKey(), $state);
    }
}
