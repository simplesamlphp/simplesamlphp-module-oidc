<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Codebooks;

/**
 * Access-control mode for the OIDC Dynamic Client Registration endpoint.
 */
enum DcrRegistrationAuthEnum: string
{
    /**
     * Open registration: anyone may POST to the registration endpoint (the
     * specification's default "open" mode). Relies on deployment-level rate
     * limiting to mitigate abuse.
     */
    case Open = 'open';

    /**
     * Registration requires a bearer Initial Access Token, provisioned
     * out-of-band (here: a configured static allow-list of tokens).
     */
    case InitialAccessToken = 'initial_access_token';
}
