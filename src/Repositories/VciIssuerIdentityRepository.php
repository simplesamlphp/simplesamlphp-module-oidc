<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Repositories;

use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Codebooks\DateFormatsEnum;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\VciIssuerIdentity;
use Throwable;

/**
 * Which issuer identities this deployment has actually issued credentials under.
 *
 * Configuration alone can not answer that. Credentials do not expire unless a deployment configures a
 * lifetime for them, so an identity used once may need to stay resolvable indefinitely, and nothing
 * else in the module records that it was ever used. Without this, changing the issuer identity is a
 * silent change: everything keeps working for as long as nobody tries to verify an older credential.
 *
 * Every identity ever used is kept rather than only the first one. A deployment which moves from one
 * identity to another and back would otherwise compare equal to what is stored and report nothing,
 * while the credentials issued in between stay unverifiable.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\Repositories\VciIssuerIdentityRepositoryTest
 */
class VciIssuerIdentityRepository extends AbstractDatabaseRepository
{
    final public const string TABLE_NAME = 'oidc_vci_issuer_identity';


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
     * Note that an identity is issued under, if this is the first time it has been seen.
     *
     * The identifier is hashed for the primary key rather than being the key itself, because a
     * `did:jwk` carries a whole public key and an RSA one runs well past what MySQL will index.
     *
     * @throws \Exception
     */
    public function recordUsage(VciIssuerIdentity $identity): void
    {
        $identifierHash = hash('sha256', $identity->getIssuer());

        if ($this->isRecorded($identifierHash)) {
            return;
        }

        try {
            $this->database->write(
                sprintf(
                    'INSERT INTO %s (identifier_hash, identifier, mode, first_used_at) ' .
                    'VALUES (:identifier_hash, :identifier, :mode, :first_used_at)',
                    $this->getTableName(),
                ),
                [
                    'identifier_hash' => $identifierHash,
                    'identifier' => $identity->getIssuer(),
                    'mode' => $identity->getMode()->value,
                    'first_used_at' => $this->helpers->dateTime()->getUtc()
                        ->format(DateFormatsEnum::DB_DATETIME->value),
                ],
            );
        } catch (Throwable $throwable) {
            // Two requests recording the same identity at once, and a secondary which had not caught up
            // when the check above ran, both arrive here on the primary key. Asking again is what tells
            // those apart from a write which genuinely failed: if the row is there now then there was
            // nothing to do, and reporting it would raise an error against a perfectly good issuance.
            if (!$this->isRecorded($identifierHash)) {
                throw $throwable;
            }
        }
    }


    /**
     * Every identity credentials have been issued under, as identifier to the mode which produced it.
     *
     * @return array<string,string>
     */
    public function getAllUsed(): array
    {
        $rows = $this->database
            ->read(sprintf('SELECT identifier, mode FROM %s', $this->getTableName()))
            ->fetchAll();

        $used = [];

        /** @var mixed $row */
        foreach ($rows as $row) {
            if (!is_array($row)) {
                continue;
            }

            /** @var mixed $identifier */
            $identifier = $row['identifier'] ?? null;
            /** @var mixed $mode */
            $mode = $row['mode'] ?? null;

            if (!is_string($identifier) || !is_string($mode)) {
                continue;
            }

            $used[$identifier] = $mode;
        }

        return $used;
    }


    /**
     * Read from the primary where the installed SimpleSAMLphp can, since a secondary which has not
     * caught up answers no to an identity recorded moments ago and turns this into an insert which
     * collides on the primary key. Deployments on an older SimpleSAMLphp fall back to a secondary
     * read, where the worst case is that same collision - which the caller treats as nothing to do.
     */
    protected function isRecorded(string $identifierHash): bool
    {
        $statement = sprintf('SELECT 1 FROM %s WHERE identifier_hash = :identifier_hash', $this->getTableName());
        $params = ['identifier_hash' => $identifierHash];

        $rows = ModuleConfig::hasPrimaryDatabaseReadCapability() ?
        $this->database->readPrimary($statement, $params)->fetchAll() :
        $this->database->read($statement, $params)->fetchAll();

        return $rows !== [];
    }
}
