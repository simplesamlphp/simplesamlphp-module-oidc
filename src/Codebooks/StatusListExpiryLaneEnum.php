<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Codebooks;

use DateTimeImmutable;

/**
 * Which kind of credential a Status List accepts, as regards expiry.
 *
 * A list holding even one credential which never expires can never be retired: that credential can be
 * presented at any point in the future, so a Relying Party asked about it has to be able to fetch the
 * list. Retirement therefore has to wait for something which never happens, and the entries behind the
 * list -- a row per index, so 131072 of them at the default capacity -- are never recovered either.
 *
 * Left to itself that spreads. Indices are handed out at random across a whole pool, so in a pool whose
 * credential configurations are a mix of expiring and non-expiring ones, practically every list takes at
 * least one non-expiring credential before it fills up, and practically no list is ever retired. One
 * credential configuration issued without a lifetime makes the storage of every credential sharing its
 * pool permanent.
 *
 * The lane is what keeps that from happening. It is fixed when a list is created, recorded on its row,
 * and part of what allocation filters candidate lists on, so the two kinds never share a list:
 *
 *  - a list in the `expiring` lane can always eventually be retired, and its entries purged;
 *  - a list in the `non_expiring` lane never can, which is the honest cost of a credential
 *    configuration left out of `vci_credential_ttls`, and is now confined to the credentials that
 *    actually chose it.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\Codebooks\StatusListExpiryLaneEnumTest
 */
enum StatusListExpiryLaneEnum: string
{
    /** Every credential in the list expires, so the list can be retired once they all have. */
    case Expiring = 'expiring';

    /** The list holds credentials which never expire, so it has to be served indefinitely. */
    case NonExpiring = 'non_expiring';


    /**
     * The lane a credential belongs in, decided by the expiry it is being issued with.
     *
     * Deliberately derived from the moment itself rather than from the credential configuration's
     * entry in `vci_credential_ttls`. The two normally agree, since that is where the moment came from,
     * but only one of them is the value which actually gets written to the entry row -- and it is
     * agreement with *that* which the lane has to have, or a list could end up holding an entry its
     * lane says is impossible. Reading configuration a second time here would be a second chance to
     * disagree, for no benefit.
     */
    public static function forExpiry(?DateTimeImmutable $expiresAt): self
    {
        return $expiresAt instanceof DateTimeImmutable ? self::Expiring : self::NonExpiring;
    }
}
