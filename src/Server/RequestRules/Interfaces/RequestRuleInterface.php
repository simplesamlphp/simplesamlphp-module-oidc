<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Interfaces;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;

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
     * @param \SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface|null $responseMode Response mode to use for error responses
     * @param HttpMethodsEnum[] $allowedServerRequestMethods Indicate allowed HTTP methods used for request
     * @return \SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface|null Result of the specific check
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException If check fails
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        ResponseModeInterface $responseMode,
        array $allowedServerRequestMethods = [HttpMethodsEnum::GET],
    ): ?ResultInterface;
}
