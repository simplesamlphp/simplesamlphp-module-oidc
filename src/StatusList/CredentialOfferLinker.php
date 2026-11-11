<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\StatusList;

use SimpleSAML\Module\oidc\Repositories\StatusListEntryRepository;

/**
 * Names, on the Status List entries of the credentials a request signed, the Credential Offer they were issued from.
 *
 * This is all the Credential Endpoint is given of the entries' storage beyond claiming an entry: linking a signed
 * credential to its offer, and nothing which could change the status of a credential, so that a later request can
 * never withdraw what an earlier one issued (OpenID4VCI 1.0 section 14.3).
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\StatusList\CredentialOfferLinkerTest
 */
class CredentialOfferLinker
{
    public function __construct(
        protected readonly StatusListEntryRepository $statusListEntryRepository,
    ) {
    }


    /**
     * @param string[] $credentialIds The `jti` of each credential the request signed with a Status List entry.
     * @return int How many of them now name the offer: all of them, or something went wrong.
     * @throws \Exception
     */
    public function link(string $offerId, array $credentialIds): int
    {
        if ($credentialIds === []) {
            return 0;
        }

        return $this->statusListEntryRepository->linkToOffer(
            $offerId,
            array_map($this->statusListEntryRepository->hashCredentialId(...), array_values($credentialIds)),
        );
    }
}
