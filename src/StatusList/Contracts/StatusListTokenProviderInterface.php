<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\StatusList\Contracts;

use SimpleSAML\Module\oidc\StatusList\Values\StatusListTokenResult;

/**
 * Produces the Status List Token to serve for a list, signing a fresh one when what is published no
 * longer represents the list.
 *
 * The two ways this can fail are deliberately distinct, because they mean opposite things to a Relying
 * Party. Returning null says the list is not something this issuer serves, so asking again will not
 * help. Throwing says a token should exist but could not be produced right now, and the caller must say
 * so rather than serve anything: a token which is merely out of date still reports a revoked credential
 * as valid, which is the one answer that must never be given.
 */
interface StatusListTokenProviderInterface
{
    /**
     * @return ?\SimpleSAML\Module\oidc\StatusList\Values\StatusListTokenResult Null when there is no such list, or
     *   it has been retired.
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException When a token is needed but can not
     * be produced -- the signing key is gone, signing failed, or concurrent changes kept superseding it.
     */
    public function getToken(string $statusListId): ?StatusListTokenResult;
}
