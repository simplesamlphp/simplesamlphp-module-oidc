<?php

namespace SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\RequestRuleInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\ResultInterface;

class StateRule implements RequestRuleInterface
{

    public function checkRule(ServerRequestInterface $request, ResultBagInterface $currentResultBag): ?ResultInterface
    {
        // TODO: Implement checkRule() method.
        return null;
    }
}
