<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Interfaces;

use Psr\Http\Message\ServerRequestInterface;
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
     * @param \SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface $currentResultBag
     *   ResultBag with all results of the checks performed to current check
     * @param array $data Data which will be available during check.
     * @param bool $useFragmentInHttpErrorResponses Indicate that in case of HTTP error responses, params should be
     *   returned in URI fragment instead of query.
     * @param string[] $allowedServerRequestMethods Indicate allowed HTTP methods used for request
     * @return \SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface|null Result of the specific check
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException If check fails
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        bool $useFragmentInHttpErrorResponses = false,
        array $allowedServerRequestMethods = ['GET'],
    ): ?ResultInterface;
}
