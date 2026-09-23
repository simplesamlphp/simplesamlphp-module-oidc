<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Services\Introspection;

use SimpleSAML\Module\oidc\ValueAbstracts\IntrospectedTokenOrigin;
use SimpleSAML\Module\oidc\ValueAbstracts\IntrospectionAuthorization;
use SimpleSAML\Module\oidc\ValueAbstracts\IntrospectionReleaseDecision;

/**
 * The default: every caller entitled to ask about a token is told everything the answer carries.
 *
 * What is then released to whom rests on the deployment's other decisions - which clients it names as
 * resource servers, and which scopes a token was granted - rather than on a per-caller policy.
 */
class PassthroughIntrospectionReleasePolicy implements IntrospectionReleasePolicyInterface
{
    public function decide(
        IntrospectionAuthorization $caller,
        IntrospectedTokenOrigin $origin,
        array $grantedScopes,
        array $tokenMembers,
    ): IntrospectionReleaseDecision {
        return IntrospectionReleaseDecision::releaseAll();
    }
}
