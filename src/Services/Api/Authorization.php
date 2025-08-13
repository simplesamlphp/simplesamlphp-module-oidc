<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Services\Api;

use SimpleSAML\Locale\Translate;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Exceptions\AuthorizationException;
use SimpleSAML\Module\oidc\ModuleConfig;
use Symfony\Component\HttpFoundation\Request;
use Throwable;

class Authorization
{
    public const KEY_TOKEN = 'token';

    public const KEY_AUTHORIZATION = 'Authorization';

    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly SspBridge $sspBridge,
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
            } catch (\Throwable $exception) {
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
        try {
            $this->requireSimpleSAMLphpAdmin();
            return;
        } catch (Throwable) {
            // Not admin, check for token.
        }

        if (empty($token = $this->findToken($request))) {
            throw new AuthorizationException(Translate::noop('Token not provided.'));
        }

        if (empty($tokenScopes = $this->moduleConfig->getApiTokenScopes($token))) {
            throw new AuthorizationException(Translate::noop('Token does not have defined scopes.'));
        }

        $hasAny = !empty(array_filter($tokenScopes, fn($tokenScope) => in_array($tokenScope, $requiredScopes, true)));

        if (!$hasAny) {
            throw new AuthorizationException(Translate::noop('Token is not authorized.'));
        }
    }

    protected function findToken(Request $request): ?string
    {
        if ($token = trim((string) $request->get(self::KEY_TOKEN))) {
            return $token;
        }

        if ($request->headers->has(self::KEY_AUTHORIZATION)) {
            return trim(
                (string) preg_replace(
                    '/^\s*Bearer\s/',
                    '',
                    (string)$request->headers->get(self::KEY_AUTHORIZATION),
                ),
            );
        }

        return null;
    }
}
