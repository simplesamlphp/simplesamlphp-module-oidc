<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Codebooks;

/**
 * What an authenticated caller of the token introspection endpoint is to this OP, which decides which
 * tokens it may be told about and whether a token this OP did not issue may be asked about elsewhere on
 * its behalf (AARC-G052 proxied token introspection).
 */
enum IntrospectionCallerRoleEnum: string
{
    /**
     * Any client which authenticates as itself, and is told only about tokens issued to it.
     */
    case Client = 'client';

    /**
     * A client the deployment named as a resource server: told about any token this OP issued, and the
     * only role on whose behalf a token this OP did not issue may be introspected upstream.
     */
    case ResourceServer = 'resource_server';

    /**
     * A client the deployment named as the upstream hub (the AS which performs proxied introspection
     * towards this OP): told about any token this OP issued, since introspecting tokens it did not
     * receive is its whole function, but never forwarded for, so that a token can not travel back to
     * where it came from.
     */
    case UpstreamHub = 'upstream_hub';

    /**
     * A logged in SimpleSAMLphp administrator, or an API token holding an introspection scope: told about
     * any token this OP issued, never forwarded for.
     */
    case Administrative = 'administrative';
}
