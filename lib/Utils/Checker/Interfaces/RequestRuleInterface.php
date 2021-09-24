<?php

namespace SimpleSAML\Module\oidc\Utils\Checker\Interfaces;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;

interface RequestRuleInterface
{
    /**
     * Get rule key, that is, rule identifier.
     * @return string
     */
    public function getKey(): string;

    /**
     * Check specific rule.
     * @param ServerRequestInterface $request
     * @param ResultBagInterface $currentResultBag ResultBag with all results of the checks performed to current check
     * @param array $data Data which will be available during check.
     * @param bool $useFragmentInHttpErrorResponses Indicate that in case of HTTP error responses, params should be
     * returned in URI fragment instead of query.
     * @param array $allowedServerRequestMethods Indicate allowed HTTP methods used for request
     * @return ResultInterface|null Result of the specific check
     * @throws OidcServerException If check fails
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        bool $useFragmentInHttpErrorResponses = false,
        array $allowedServerRequestMethods = ['GET']
    ): ?ResultInterface;
}
