<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils;

use League\OAuth2\Server\Entities\UserEntityInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClaimSetInterface;
use SimpleSAML\Module\oidc\ModuleConfig;

/**
 * The user claims which go into the JWT access token next to 'sub': the identity claims and the configured
 * access token claims (ModuleConfig::getIdentityClaims(), getAccessTokenClaims()), each only when a granted
 * scope carries it, so the token never says more than the UserInfo endpoint would for the same grant. The
 * 'claims' request parameter (OpenID Connect Core 1.0 section 5.5) targets the ID token and the UserInfo
 * endpoint and plays no part here.
 *
 * Resolved once, when the token is minted, from the user record as it is then; the token is a snapshot.
 */
class AccessTokenClaimsResolver
{
    public function __construct(
        protected readonly ClaimTranslatorExtractor $claimTranslatorExtractor,
        protected readonly ModuleConfig $moduleConfig,
    ) {
    }


    /**
     * @param array<array-key, string|\League\OAuth2\Server\Entities\ScopeEntityInterface> $grantedScopes
     * @return array<non-empty-string, mixed> Claim name => value, in the order the extractor releases them.
     * @throws \RuntimeException When an identity claim's value is not a non-empty string.
     */
    public function resolve(UserEntityInterface&ClaimSetInterface $user, array $grantedScopes): array
    {
        $allowedClaimNames = [
            ...$this->moduleConfig->getIdentityClaims(),
            ...$this->moduleConfig->getAccessTokenClaims(),
        ];

        if ($allowedClaimNames === []) {
            return [];
        }

        $accessTokenClaims = [];

        // Neither list can name 'sub' or another claim the token envelope writes (ModuleConfig refuses those), so
        // what passes here can not collide with the envelope.
        /** @psalm-suppress MixedAssignment */
        foreach ($this->claimTranslatorExtractor->extract($grantedScopes, $user->getClaims()) as $claimName => $value) {
            if (is_string($claimName) && $claimName !== '' && in_array($claimName, $allowedClaimNames, true)) {
                $accessTokenClaims[$claimName] = $value;
            }
        }

        return $accessTokenClaims;
    }
}
