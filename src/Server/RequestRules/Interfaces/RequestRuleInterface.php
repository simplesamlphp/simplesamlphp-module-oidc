<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Interfaces;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;

/**
 * The generic parameter T describes the type of value the rule yields into the result bag. It is
 * bound by each concrete rule (via `@extends AbstractRule<...>`) and consumed by the ResultBag,
 * which uses it to infer the value type when a result is fetched by its rule class-string.
 *
 * @template-covariant T
 */
interface RequestRuleInterface
{
    /**
     * Get rule key, that is, rule identifier.
     * @return string
     */
    public function getKey(): string;

    /**
     * Check specific rule.
     *
     * @param \SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface $currentResultBag
     *   ResultBag with all results of the checks performed to current check
     * @param array $data Data which will be available during check.
     * @param ResponseModeInterface $responseMode Response mode to use for error responses
     * @param HttpMethodsEnum[] $allowedServerRequestMethods Indicate allowed HTTP methods used for request
     *
     * @return \SimpleSAML\Module\oidc\Server\RequestRules\Result<mixed>|null Result of the specific check
     *   (the concrete value type T is bound per rule and surfaced via the ResultBag accessors)
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException If check fails
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        ResponseModeInterface $responseMode = new QueryResponseMode(),
        array $allowedServerRequestMethods = [HttpMethodsEnum::GET],
    ): ?Result;
}
