<?php

namespace SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces;

use Psr\Http\Message\ServerRequestInterface;

interface RequestRuleInterface
{
    /**
     * Get rule key, that is, rule identifier.
     * @return string
     */
    public static function getKey(): string;

    /**
     * Check specific rule.
     * @param ServerRequestInterface $request
     * @param ResultBagInterface $currentResultBag ResultBag with all results of the checks performed to current check
     * @param array $data Data which will be available during check.
     * @return ResultInterface|null Result of the specific check
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        array $data
    ): ?ResultInterface;
}
