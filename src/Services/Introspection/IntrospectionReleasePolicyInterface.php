<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Services\Introspection;

use SimpleSAML\Module\oidc\ValueAbstracts\IntrospectedTokenOrigin;
use SimpleSAML\Module\oidc\ValueAbstracts\IntrospectionAuthorization;
use SimpleSAML\Module\oidc\ValueAbstracts\IntrospectionReleaseDecision;

/**
 * Decides, per caller, how much of an active token's introspection answer that caller is told.
 *
 * RFC 7662 section 2.2 lets an authorization server "respond differently to different protected resources
 * making the same request", for instance by limiting "which scopes from a given token are returned for each
 * protected resource", and AARC-G052 section 3 lets an authorization server performing proxied token
 * introspection do the same. This is where a deployment makes that choice. It is consulted once per answer,
 * for a token this OP issued and for one answered upstream alike, after the caller has been established as
 * entitled to ask about the token, and only for a token which is active: a policy can turn an active answer
 * into an inactive one, never the other way round.
 *
 * An implementation is configured by class name, and constructed with the arguments configured next to it
 * (see ModuleConfig::OPTION_API_OAUTH2_TOKEN_INTROSPECTION_RELEASE_POLICY). It must not throw for a token it
 * has no opinion about; what it throws is answered as the OP's failure (a server_error), not as an inactive
 * token, and so is a decision it builds with a name no decision may withhold.
 */
interface IntrospectionReleasePolicyInterface
{
    /**
     * @param \SimpleSAML\Module\oidc\ValueAbstracts\IntrospectionAuthorization $caller Who asked, and in which
     * role.
     * @param \SimpleSAML\Module\oidc\ValueAbstracts\IntrospectedTokenOrigin $origin Whether the token was
     * issued here, and if not, by whom.
     * @param string[] $grantedScopes The scopes the token carries.
     * @param array<array-key, mixed> $tokenMembers The answer as it stands before the decision is applied:
     * for a token issued here, its RFC 7662 members without the user claims, which are read only for the
     * scopes the decision releases; for a token answered upstream, that answer.
     */
    public function decide(
        IntrospectionAuthorization $caller,
        IntrospectedTokenOrigin $origin,
        array $grantedScopes,
        array $tokenMembers,
    ): IntrospectionReleaseDecision;
}
