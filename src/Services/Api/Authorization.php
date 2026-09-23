<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Services\Api;

use SimpleSAML\Locale\Translate;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Exceptions\AuthorizationException;
use SimpleSAML\Module\oidc\Exceptions\InsufficientScopeException;
use SimpleSAML\Module\oidc\Exceptions\MissingTokenException;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use Symfony\Component\HttpFoundation\Request;
use Throwable;

class Authorization
{
    public const string KEY_TOKEN = 'token';

    public const string KEY_AUTHORIZATION = 'Authorization';

    /**
     * Who a request authorized by a logged in SimpleSAMLphp administrator is made by. The session says that
     * the user is an administrator, not which one.
     */
    public const string ADMIN_PRINCIPAL = 'simplesamlphp-admin';


    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly SspBridge $sspBridge,
        protected readonly RequestParamsResolver $requestParamsResolver,
        protected readonly Helpers $helpers,
        protected readonly ApiTokenPrincipalResolver $apiTokenPrincipalResolver,
    ) {
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\AuthorizationException
     */
    public function requireSimpleSAMLphpAdmin(bool $forceAdminAuthentication = false): void
    {
        if ($forceAdminAuthentication) {
            try {
                $this->sspBridge->utils()->auth()->requireAdmin();
            } catch (Throwable $exception) {
                throw new AuthorizationException(
                    Translate::noop('Unable to initiate admin authentication.'),
                    previous: $exception,
                );
            }
        }

        if (! $this->sspBridge->utils()->auth()->isAdmin()) {
            throw new AuthorizationException(Translate::noop('SimpleSAMLphp Admin access required.'));
        }
    }


    /**
     * @param \SimpleSAML\Module\oidc\Codebooks\ApiScopesEnum[] $requiredScopes
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\AuthorizationException
     */
    public function requireTokenForAnyOfScope(Request $request, array $requiredScopes): void
    {
        $this->authorizeForAnyOfScope($request, $requiredScopes);
    }


    /**
     * {@see requireTokenForAnyOfScope()}, saying who the request is made by: for an endpoint whose answer
     * depends on who is asking, and not only on whether they may ask at all.
     *
     * @param \SimpleSAML\Module\oidc\Codebooks\ApiScopesEnum[] $requiredScopes
     * @return string ADMIN_PRINCIPAL for a logged in SimpleSAMLphp administrator; for an API token, who it
     * stands for as {@see ApiTokenPrincipalResolver} resolves it: its configured name, or a fingerprint.
     * Never the token itself. Two tokens configured under one name are therefore one caller.
     * @throws \SimpleSAML\Module\oidc\Exceptions\AuthorizationException
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function requireCallerForAnyOfScope(Request $request, array $requiredScopes): string
    {
        $token = $this->authorizeForAnyOfScope($request, $requiredScopes);

        return is_null($token) ? self::ADMIN_PRINCIPAL : $this->apiTokenPrincipalResolver->resolve($token);
    }


    /**
     * @param \SimpleSAML\Module\oidc\Codebooks\ApiScopesEnum[] $requiredScopes
     * @return ?string The API token the request was authorized with, or null when an administrator's
     * session authorized it.
     * @throws \SimpleSAML\Module\oidc\Exceptions\AuthorizationException
     */
    protected function authorizeForAnyOfScope(Request $request, array $requiredScopes): ?string
    {
        try {
            $this->requireSimpleSAMLphpAdmin();
            return null;
        } catch (Throwable) {
            // Not admin, check for token.
        }

        if (empty($token = $this->findToken($request))) {
            throw new AuthorizationException(Translate::noop('Authorization token not provided.'));
        }

        if (empty($tokenScopes = $this->moduleConfig->getApiTokenScopes($token))) {
            throw new AuthorizationException(Translate::noop('Authorization token does not have defined scopes.'));
        }

        $hasAny = !empty(array_filter($tokenScopes, fn($tokenScope) => in_array($tokenScope, $requiredScopes, true)));

        if (!$hasAny) {
            throw new AuthorizationException(Translate::noop('Authorization token is not authorized for this action.'));
        }

        return $token;
    }


    /**
     * Authorize a state changing request, and say who it is being made by.
     *
     * Deliberately not {@see requireTokenForAnyOfScope()}, which is right for the endpoints it serves
     * and wrong for this kind. That method accepts an authenticated SimpleSAMLphp admin session before
     * it ever looks at a token, which means a request carrying an administrator's cookies is authorized
     * whatever caused the browser to send it; and it falls back to reading the token from a request
     * parameter, which puts a bearer secret in access logs, browser history and any Referer that
     * follows. Neither matters much for reading, and both matter for withdrawing a credential.
     *
     * So: the Authorization header, and nothing else. A signed in administrator acts through the
     * administration screens, which have their own authorization and their own cross-site protection.
     *
     * @param \SimpleSAML\Module\oidc\Codebooks\ApiScopesEnum[] $requiredScopes
     * @return string Who the request is made by, for recording against what it changes. Never the
     * token itself.
     * @throws \SimpleSAML\Module\oidc\Exceptions\MissingTokenException When the request carried no
     * token at all, which calls for a different challenge than one that arrived and was refused.
     * @throws \SimpleSAML\Module\oidc\Exceptions\InsufficientScopeException When the token is known
     * and does not cover this action, which no amount of retrying will change.
     * @throws \SimpleSAML\Module\oidc\Exceptions\AuthorizationException When the token is not usable.
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function requireBearerTokenForAnyOfScope(Request $request, array $requiredScopes): string
    {
        $token = $this->helpers->http()->getBearerToken($request->headers->get(self::KEY_AUTHORIZATION));

        if ($token === null || trim($token) === '') {
            throw new MissingTokenException(
                Translate::noop('Authorization token not provided in the Authorization header.'),
            );
        }

        $tokenScopes = $this->moduleConfig->getApiTokenScopes($token);

        // No scopes at all covers both a token which is not configured here and one which is
        // configured without any, and the two are answered the same way on purpose: saying which is
        // which would let a caller test whether a token exists.
        if (empty($tokenScopes)) {
            throw new AuthorizationException(Translate::noop('Authorization token does not have defined scopes.'));
        }

        $hasAny = !empty(array_filter($tokenScopes, fn(mixed $tokenScope): bool => in_array(
            $tokenScope,
            $requiredScopes,
            true,
        )));

        if (!$hasAny) {
            // A good token which does not cover this. Distinct from the two failures above, because
            // the caller is authenticated and rotating its token would not help.
            throw new InsufficientScopeException(
                Translate::noop('Authorization token is not authorized for this action.'),
            );
        }

        return $this->apiTokenPrincipalResolver->resolve($token);
    }


    protected function findToken(Request $request): ?string
    {
        $bearerToken = $this->helpers->http()->getBearerToken($request->headers->get(self::KEY_AUTHORIZATION));
        if ($bearerToken !== null) {
            return $bearerToken;
        }

        // Fallback to token parameter.
        $token = $this->requestParamsResolver->getFromRequestBasedOnAllowedMethods(
            self::KEY_TOKEN,
            $request,
            [
                HttpMethodsEnum::GET,
                HttpMethodsEnum::POST,
            ],
        );
        if ($token = trim((string) $token)) {
            return $token;
        }

        return null;
    }
}
