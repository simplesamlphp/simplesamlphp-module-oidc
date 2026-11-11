<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\VerifiableCredentials\Values;

/**
 * A Credential Offer just made: the URI a wallet is sent to, and the id under which the offer is recorded.
 *
 * The id is not the pre-authorized code nor the issuer state, both of which redeem the offer: it is what the maker
 * of the offer keeps in its own records and logs, and asks about later.
 *
 * @see \SimpleSAML\Module\oidc\Factories\CredentialOfferUriFactory
 */
class BuiltCredentialOffer
{
    public function __construct(
        protected readonly string $uri,
        protected readonly string $offerId,
    ) {
    }


    public function getUri(): string
    {
        return $this->uri;
    }


    public function getOfferId(): string
    {
        return $this->offerId;
    }
}
