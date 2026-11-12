<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Codebooks;

/**
 * What came of noting on a Credential Offer's record that an access token was minted for the offer
 * (CredentialOfferRepository::recordRedemption()).
 */
enum CredentialOfferRedemptionEnum
{
    /** The record is kept at least until the token expires, and notes when the offer was first redeemed. */
    case Recorded;

    /** The offer has been withdrawn, so the token is not to be handed out. */
    case Withdrawn;

    /** The record is not there, or the write did not take: the token could not be listed under the offer. */
    case NotRecorded;
}
