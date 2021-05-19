<?php

namespace SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces;

use Psr\Http\Message\ServerRequestInterface;

interface RequestRuleInterface
{
    /**
     * Check specific rule.
     * @param ServerRequestInterface $request
     * @param ResultBagInterface $currentResultBag ResultBag with all results of the checks performed up to now
     * @return ResultInterface|null Result of the specific check
     */
    public function checkRule(ServerRequestInterface $request, ResultBagInterface $currentResultBag): ?ResultInterface;
}
