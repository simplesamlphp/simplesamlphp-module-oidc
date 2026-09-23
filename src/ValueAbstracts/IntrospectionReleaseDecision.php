<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\ValueAbstracts;

use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;

/**
 * What an introspection release policy decided for one answer: deny it, or release it with fewer scopes and
 * without some named members.
 *
 * A decision rather than a rewritten response, so that the order it is applied in is fixed, and applied by
 * the endpoint rather than left to each policy: the scopes are reduced first, the user claims are then taken
 * from the reduced set (so a scope taken away can not leave its claims behind), the response is assembled,
 * and the withheld names are removed from it last (so that nothing assembled later can put one back, 'sub'
 * included, which is a member of the token as well as a user claim).
 *
 * A decision can only take away. It can not add a scope the token was not granted, and it can not touch the
 * members listed in PROTECTED_MEMBERS.
 *
 * @see \SimpleSAML\Module\oidc\Services\Introspection\IntrospectionReleasePolicyInterface
 */
class IntrospectionReleaseDecision
{
    /**
     * Members no decision may withhold. 'active' is the answer itself. The others describe the token rather
     * than its subject, and AARC-G052 section 3 has a proxy "MUST NOT change claims related to the token
     * itself (i.e. the iss, exp, iat, nbf, token_type, client_id, and jti claims value of the response)"; the
     * same set holds on the local path. 'aud' is added although G052 lets a proxy change it: the audience is
     * what a resource server judges the token's use by, and a policy which could remove it would remove the
     * evidence that judgement rests on.
     */
    public const array PROTECTED_MEMBERS = [
        'active',
        ClaimsEnum::Iss->value,
        ClaimsEnum::Exp->value,
        ClaimsEnum::Iat->value,
        ClaimsEnum::Nbf->value,
        'token_type',
        ClaimsEnum::ClientId->value,
        ClaimsEnum::Jti->value,
        ClaimsEnum::Aud->value,
    ];


    /**
     * @param ?string[] $scopesToRelease Null to release every scope the token was granted.
     * @param string[] $withheldMembers
     */
    protected function __construct(
        protected readonly bool $isDenied,
        protected readonly ?array $scopesToRelease,
        protected readonly array $withheldMembers,
    ) {
    }


    /**
     * The answer as the endpoint would give it without a policy.
     */
    public static function releaseAll(): self
    {
        return new self(false, null, []);
    }


    /**
     * The caller is not to be told about this token. It is answered as an inactive token, and nothing says why.
     */
    public static function deny(): self
    {
        return new self(true, null, []);
    }


    /**
     * Both lists are written by whoever writes the policy, and are checked here rather than trusted.
     *
     * @param ?mixed[] $scopesToRelease The scopes (strings) the caller may be told the token carries, or null
     * for every scope it was granted. Only ever a restriction: a scope the token was not granted is not
     * released by being named here.
     * @param mixed[] $withheldMembers Names (strings) of members to leave out of the answer: a user claim,
     * 'sub', 'username', or a member of a foreign answer.
     * @throws \SimpleSAML\Error\ConfigurationError When a name is not a non-empty string, or names a member
     * in PROTECTED_MEMBERS: the policy is misconfigured, and silently keeping the member would hide that.
     */
    public static function release(?array $scopesToRelease = null, array $withheldMembers = []): self
    {
        $validatedScopes = null;

        if (!is_null($scopesToRelease)) {
            $validatedScopes = [];

            /** @psalm-suppress MixedAssignment */
            foreach ($scopesToRelease as $scope) {
                if (!is_string($scope) || $scope === '') {
                    throw new ConfigurationError(
                        'An introspection release decision names a scope which is not a non-empty string.',
                    );
                }

                $validatedScopes[] = $scope;
            }
        }

        $validatedMembers = [];

        /** @psalm-suppress MixedAssignment */
        foreach ($withheldMembers as $member) {
            if (!is_string($member) || $member === '') {
                throw new ConfigurationError(
                    'An introspection release decision withholds a member name which is not a non-empty string.',
                );
            }

            if (in_array($member, self::PROTECTED_MEMBERS, true)) {
                throw new ConfigurationError(
                    sprintf(
                        'An introspection release decision may not withhold the member %s, which describes the ' .
                        'token itself (protected members: %s).',
                        $member,
                        implode(', ', self::PROTECTED_MEMBERS),
                    ),
                );
            }

            $validatedMembers[] = $member;
        }

        return new self(false, $validatedScopes, $validatedMembers);
    }


    public function isDenied(): bool
    {
        return $this->isDenied;
    }


    /**
     * The granted scopes this decision releases, in the order the token carries them.
     *
     * @param string[] $grantedScopes
     * @return string[]
     */
    public function releasedScopesOf(array $grantedScopes): array
    {
        if (is_null($this->scopesToRelease)) {
            return array_values($grantedScopes);
        }

        return array_values(
            array_filter(
                $grantedScopes,
                fn(string $scope): bool => in_array($scope, (array)$this->scopesToRelease, true),
            ),
        );
    }


    /**
     * The assembled answer without the withheld members; the last step of applying a decision.
     *
     * @param array<array-key, mixed> $response
     * @return array<array-key, mixed>
     */
    public function withholdFrom(array $response): array
    {
        foreach ($this->withheldMembers as $member) {
            unset($response[$member]);
        }

        return $response;
    }


    /**
     * @return string[]
     */
    public function getWithheldMembers(): array
    {
        return $this->withheldMembers;
    }
}
