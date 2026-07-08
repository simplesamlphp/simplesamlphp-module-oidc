<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\RequestRuleInterface;
use SimpleSAML\Module\oidc\Services\AuthenticationService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;
use SimpleSAML\OpenID\Codebooks\ScopesEnum;

/**
 * @template T
 * @implements RequestRuleInterface<T>
 */
abstract class AbstractRule implements RequestRuleInterface
{
    public function __construct(
        protected RequestParamsResolver $requestParamsResolver,
        protected Helpers $helpers,
    ) {
    }

    /**
     * @inheritDoc
     */
    public function getKey(): string
    {
        return static::class;
    }

    /**
     * Check if the authorization request is an OpenID Connect request
     * (designated by the openid scope), as opposed to a plain OAuth 2.0
     * request. Scope is resolved from all request params, including the ones
     * from Request Object / Request URI, if present.
     *
     * @param \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum[] $allowedServerRequestMethods
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     */
    protected function isOidcAuthorizationRequest(
        ServerRequestInterface $request,
        array $allowedServerRequestMethods = [HttpMethodsEnum::GET],
    ): bool {
        $scope = $this->requestParamsResolver->getAsStringBasedOnAllowedMethods(
            ParamsEnum::Scope->value,
            $request,
            $allowedServerRequestMethods,
        ) ?? '';

        return in_array(ScopesEnum::OpenId->value, explode(' ', $scope), true);
    }

    /**
     * Propagate the login_hint authorization request parameter (if present) into the given login params as the
     * pre-filled username, so it survives a rule-initiated re-authentication (e.g. prompt=login or expired max_age),
     * where the normal AuthenticationService propagation path is bypassed. Best-effort, mirroring
     * AuthenticationService::resolveLoginParams().
     *
     * @param array<string,mixed> $loginParams
     * @param \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum[] $allowedServerRequestMethods
     */
    protected function addLoginHintParam(
        array &$loginParams,
        ServerRequestInterface $request,
        array $allowedServerRequestMethods = [HttpMethodsEnum::GET],
    ): void {
        $loginHint = $this->requestParamsResolver->getAsStringBasedOnAllowedMethods(
            ParamsEnum::LoginHint->value,
            $request,
            $allowedServerRequestMethods,
        );

        if ($loginHint === null) {
            return;
        }

        $loginParams[AuthenticationService::LOGIN_PARAM_USERNAME] = $loginHint;
    }
}
