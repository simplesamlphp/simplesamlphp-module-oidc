<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Repositories;

use DateTimeImmutable;
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Codebooks\CredentialOfferRedemptionEnum;
use SimpleSAML\Module\oidc\Entities\Traits\FormatForDatabaseTrait;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\CredentialOfferRecord;

/**
 * The record of every Credential Offer, which tells the API caller that made an offer what it produced.
 *
 * A record is written before the pre-authorized code or the issuer state which redeems the offer, so that they can
 * name it; one whose code then fails to be stored is left behind, and removeExpired() takes it once it could no
 * longer have been redeemed. It is kept at least until the offer stops being redeemable and, once access tokens are
 * minted for it, until the last of them expires (recordRedemption()): a token which still lives can still buy
 * credentials, and every one of those has to be listable under the offer. After that it goes once no status entry
 * names it any more, which linkage cleanup sees to as the offer's credentials expire.
 *
 * Every read is from the primary: the record is read moments after it was written or changed (a token minted, a
 * credential issued), which a database secondary may not have seen yet.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\Repositories\CredentialOfferRepositoryTest
 */
class CredentialOfferRepository extends AbstractDatabaseRepository
{
    use FormatForDatabaseTrait;


    final public const string TABLE_NAME = 'oidc_vci_credential_offer';


    public function __construct(
        ModuleConfig $moduleConfig,
        Database $database,
        ?ProtocolCache $protocolCache,
        protected readonly Helpers $helpers,
    ) {
        parent::__construct($moduleConfig, $database, $protocolCache);
    }


    public function getTableName(): string
    {
        return $this->database->applyPrefix(self::TABLE_NAME);
    }


    /**
     * @throws \JsonException
     * @throws \Exception When the record can not be written.
     */
    public function persist(CredentialOfferRecord $offer): void
    {
        $redeemedAt = $offer->getRedeemedAt();
        $withdrawnAt = $offer->getWithdrawnAt();

        $this->database->write(
            sprintf(
                'INSERT INTO %s (id, owner, credential_configuration_ids, grant_type, created_at, redeemable_until, ' .
                'retained_until, redeemed_at, withdrawn_at) VALUES (:id, :owner, :credential_configuration_ids, ' .
                ':grant_type, :created_at, :redeemable_until, :retained_until, :redeemed_at, :withdrawn_at)',
                $this->getTableName(),
            ),
            [
                'id' => $offer->getId(),
                'owner' => $offer->getOwner(),
                'credential_configuration_ids' => json_encode(
                    $offer->getCredentialConfigurationIds(),
                    JSON_THROW_ON_ERROR,
                ),
                'grant_type' => $offer->getGrantType(),
                'created_at' => $this->formatForDatabase($offer->getCreatedAt()),
                'redeemable_until' => $this->formatForDatabase($offer->getRedeemableUntil()),
                'retained_until' => $this->formatForDatabase($offer->getRetainedUntil()),
                'redeemed_at' => $redeemedAt instanceof DateTimeImmutable ?
                    $this->formatForDatabase($redeemedAt) :
                    null,
                'withdrawn_at' => $withdrawnAt instanceof DateTimeImmutable ?
                    $this->formatForDatabase($withdrawnAt) :
                    null,
            ],
        );
    }


    /**
     * @throws \RuntimeException When the stored row does not hold a credential offer record.
     */
    public function find(string $id): ?CredentialOfferRecord
    {
        $rows = $this->database->readPrimary(
            "SELECT * FROM {$this->getTableName()} WHERE id = :id",
            ['id' => $id],
        )->fetchAll();

        /** @var mixed $row */
        $row = $rows === [] ? null : current($rows);

        return is_array($row) ? CredentialOfferRecord::fromRow($row) : null;
    }


    /**
     * Note that an access token was minted for the offer: keep the record at least until the token expires, never
     * shortening what an earlier token asked for, and note when the offer was first redeemed. A withdrawn offer is
     * left as it is.
     *
     * Confirmed on the primary afterwards rather than by the affected row count, which MySQL reports as zero for a
     * row the statement matched and left as it was (a second token expiring sooner than the first, say). The record
     * read back also tells a withdrawn offer from a missing one, whether the withdrawal landed before this write or
     * after it: either way the token is not to be handed out.
     *
     * @param \DateTimeImmutable $tokenExpiresAt The expiry of the token as it was stored, so that neither a calendar
     * interval nor a lifetime raised between offer and redemption can let the token outlive the record.
     * @throws \Exception
     * @throws \RuntimeException When the stored row does not hold a credential offer record.
     */
    public function recordRedemption(string $id, DateTimeImmutable $tokenExpiresAt): CredentialOfferRedemptionEnum
    {
        // Each value under its own placeholder name: PDO turns named placeholders into positional ones for some
        // drivers, and a repeated name then binds only its first occurrence.
        $this->database->write(
            sprintf(
                'UPDATE %s SET ' .
                'retained_until = CASE WHEN retained_until < :expires_at THEN :raised_until ELSE retained_until END, ' .
                'redeemed_at = COALESCE(redeemed_at, :redeemed_at) ' .
                'WHERE id = :id AND withdrawn_at IS NULL',
                $this->getTableName(),
            ),
            [
                'expires_at' => $this->formatForDatabase($tokenExpiresAt),
                'raised_until' => $this->formatForDatabase($tokenExpiresAt),
                'redeemed_at' => $this->formatForDatabase($this->helpers->dateTime()->getUtc()),
                'id' => $id,
            ],
        );

        $offer = $this->find($id);

        if (!$offer instanceof CredentialOfferRecord) {
            return CredentialOfferRedemptionEnum::NotRecorded;
        }

        if ($offer->getWithdrawnAt() instanceof DateTimeImmutable) {
            return CredentialOfferRedemptionEnum::Withdrawn;
        }

        // Compared to the second, as the moments are stored.
        if (
            !$offer->getRedeemedAt() instanceof DateTimeImmutable ||
            $offer->getRetainedUntil()->getTimestamp() < $tokenExpiresAt->getTimestamp()
        ) {
            return CredentialOfferRedemptionEnum::NotRecorded;
        }

        return CredentialOfferRedemptionEnum::Recorded;
    }


    /**
     * Withdraw the offer, so that it buys nothing more: neither a token for its code or issuer state, nor a credential
     * for a token minted for it. Credentials already issued from it are left as they are.
     *
     * A conditional write, so that of several requests withdrawing the offer at once only one is told it did.
     *
     * @return bool Whether this call is what withdrew the offer: false when it was withdrawn already, or is not
     * recorded, or the write did not take. The record, read again, tells which.
     * @throws \Exception
     */
    public function withdraw(string $id): bool
    {
        $affected = $this->database->write(
            sprintf(
                'UPDATE %s SET withdrawn_at = :withdrawn_at WHERE id = :id AND withdrawn_at IS NULL',
                $this->getTableName(),
            ),
            [
                'withdrawn_at' => $this->formatForDatabase($this->helpers->dateTime()->getUtc()),
                'id' => $id,
            ],
        );

        return $affected === 1;
    }


    /**
     * Remove the records kept long enough which no status entry names any more.
     *
     * Both conditions are in the DELETE itself rather than in ids selected beforehand, so that no record is removed
     * on a finding which was already out of date when the removal ran. A credential linked to a record while this
     * runs, and whose record is removed all the same, is not handed out: the Credential Endpoint asks for the record
     * again after linking (CredentialIssuerCredentialController). Every access token a wallet was given for a
     * record removed here has expired, since the record is kept until the latest of their expiries.
     *
     * @throws \Exception
     */
    public function removeExpired(): void
    {
        $offerTableName = $this->getTableName();
        $entryTableName = $this->database->applyPrefix(StatusListEntryRepository::TABLE_NAME);

        $this->database->write(
            "DELETE FROM $offerTableName WHERE retained_until < :now AND NOT EXISTS (" .
            "SELECT 1 FROM $entryTableName WHERE $entryTableName.offer_id = $offerTableName.id)",
            ['now' => $this->formatForDatabase($this->helpers->dateTime()->getUtc())],
        );
    }
}
