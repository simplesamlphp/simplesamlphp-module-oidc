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
use SimpleSAML\Module\oidc\ValueAbstracts\ApiCaller;
use SimpleSAML\Module\oidc\ValueAbstracts\CredentialConfigurationLimit;
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
     * Authorize a request by a logged in SimpleSAMLphp administrator, or by an API token holding one of the scopes.
     *
     * @param \SimpleSAML\Module\oidc\Codebooks\ApiScopesEnum[] $requiredScopes
     * @return ?\SimpleSAML\Module\oidc\ValueAbstracts\ApiCaller Null for an administrator's session, which stands
     * for no API principal and may act on every credential configuration. For an API token, who it stands for and
     * the credential configurations it is configured with, which are none without a list. Told apart by type, never
     * by a principal's string: an operator could give a token any name, {@see ADMIN_PRINCIPAL} included.
     * @throws \SimpleSAML\Module\oidc\Exceptions\AuthorizationException
     * @throws \SimpleSAML\Error\ConfigurationError When who the token stands for, or its credential configurations,
     * can not be read from the configuration.
     */
    public function requireAdminOrTokenForAnyOfScope(Request $request, array $requiredScopes): ?ApiCaller
    {
        $token = $this->authorizeForAnyOfScope($request, $requiredScopes);

        if (is_null($token)) {
            return null;
        }

        return new ApiCaller(
            $this->apiTokenPrincipalResolver->resolve($token),
            $this->credentialConfigurationLimitOf($token),
        );
    }


    /**
     * Authorize a request by a logged in SimpleSAMLphp administrator, or by an API token holding one of the scopes
     * in the Authorization header, and say who it is made by: for an endpoint whose answer depends on who is asking,
     * and not only on whether they may ask at all.
     *
     * Not {@see requireAdminOrTokenForAnyOfScope()}, which falls back to reading the API token from the `token`
     * request parameter. At the token introspection endpoint, which this serves, that parameter is the token to be
     * introspected (RFC 7662 section 2.1), and it would be looked up as an API token whenever the caller sent none,
     * so that a client whose credentials were refused would be told about an API token it never sent.
     *
     * @param \SimpleSAML\Module\oidc\Codebooks\ApiScopesEnum[] $requiredScopes
     * @return string ADMIN_PRINCIPAL for a logged in SimpleSAMLphp administrator; for an API token, who it
     * stands for as {@see ApiTokenPrincipalResolver} resolves it: its configured name, or a fingerprint.
     * Never the token itself. Two tokens configured under one name are therefore one caller.
     * @throws \SimpleSAML\Module\oidc\Exceptions\MissingTokenException When the request is not an administrator's
     * and carries no token in the Authorization header.
     * @throws \SimpleSAML\Module\oidc\Exceptions\InsufficientScopeException When the token is known and holds none
     * of the scopes.
     * @throws \SimpleSAML\Module\oidc\Exceptions\AuthorizationException When the token is not usable.
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function requireCallerForAnyOfScope(Request $request, array $requiredScopes): string
    {
        try {
            $this->requireSimpleSAMLphpAdmin();
            return self::ADMIN_PRINCIPAL;
        } catch (Throwable) {
            // Not admin, check for token.
        }

        return $this->apiTokenPrincipalResolver->resolve(
            $this->bearerTokenForAnyOfScope($request, $requiredScopes),
        );
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
     * Deliberately not {@see requireAdminOrTokenForAnyOfScope()}, which is right for the endpoints it serves
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
     * @return \SimpleSAML\Module\oidc\ValueAbstracts\ApiCaller Who the request is made by, for recording
     * against what it changes, never the token itself; and the credential configurations the token is
     * configured with, which are none without a list.
     * @throws \SimpleSAML\Module\oidc\Exceptions\MissingTokenException When the request carried no
     * token at all, which calls for a different challenge than one that arrived and was refused.
     * @throws \SimpleSAML\Module\oidc\Exceptions\InsufficientScopeException When the token is known
     * and does not cover this action, which no amount of retrying will change.
     * @throws \SimpleSAML\Module\oidc\Exceptions\AuthorizationException When the token is not usable.
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function requireBearerTokenForAnyOfScope(Request $request, array $requiredScopes): ApiCaller
    {
        $token = $this->bearerTokenForAnyOfScope($request, $requiredScopes);

        return new ApiCaller(
            $this->apiTokenPrincipalResolver->resolve($token),
            $this->credentialConfigurationLimitOf($token),
        );
    }


    /**
     * The API token in the request's Authorization header, when it holds one of the scopes.
     *
     * @param \SimpleSAML\Module\oidc\Codebooks\ApiScopesEnum[] $requiredScopes
     * @throws \SimpleSAML\Module\oidc\Exceptions\MissingTokenException
     * @throws \SimpleSAML\Module\oidc\Exceptions\InsufficientScopeException
     * @throws \SimpleSAML\Module\oidc\Exceptions\AuthorizationException
     */
    protected function bearerTokenForAnyOfScope(Request $request, array $requiredScopes): string
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

        return $token;
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    protected function credentialConfigurationLimitOf(string $token): CredentialConfigurationLimit
    {
        return CredentialConfigurationLimit::fromConfiguredIds(
            $this->moduleConfig->getApiTokenCredentialConfigurationIds($token),
        );
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
