<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Entities;

use DateTimeImmutable;
use DateTimeZone;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Entities\IssuerStateEntity;

/**
 * An `issuer_state` the Credential Issuer minted for a Credential Offer: the value, the moment it was
 * created and the moment it stops being usable, and whether it has been revoked.
 *
 * Its factory is the only thing in `src/` which constructs one, and the repository stores `getState()` as
 * the row on INSERT and UPDATE alike. Unlike the Pushed Authorization Request entity it has no expiry
 * check of its own: the repository's `findValid()` compares the expiry moment with the current UTC one
 * itself, and revokes by calling `revoke()` and updating the row. The expiry getter is `getExpirestAt()`,
 * spelling and all; a rename touches the repository too, so it is noted rather than changed.
 */
#[CoversClass(IssuerStateEntity::class)]
class IssuerStateEntityTest extends TestCase
{
    /**
     * Sixty four characters, as the factory mints it (a sha256 hex digest) and as much as it accepts.
     */
    protected const string VALUE = '3b4d8f1e6a2c9075d1e8f4a6b2c3d5e7f9a1b3c5d7e9f2a4b6c8d0e2f4a6b8c0';

    protected const string CREATED_AT = '2026-09-19 14:00:00';

    protected const string EXPIRES_AT = '2026-09-19 14:10:00';


    protected function moment(string $moment, string $timezone = 'UTC'): DateTimeImmutable
    {
        return new DateTimeImmutable($moment, new DateTimeZone($timezone));
    }


    protected function sut(
        bool $isRevoked = false,
        ?DateTimeImmutable $createdAt = null,
        ?DateTimeImmutable $expiresAt = null,
    ): IssuerStateEntity {
        return new IssuerStateEntity(
            self::VALUE,
            $createdAt ?? $this->moment(self::CREATED_AT),
            $expiresAt ?? $this->moment(self::EXPIRES_AT),
            $isRevoked,
        );
    }


    public function testCarriesWhatItWasGiven(): void
    {
        $createdAt = $this->moment(self::CREATED_AT);
        $expiresAt = $this->moment(self::EXPIRES_AT);

        $entity = $this->sut(createdAt: $createdAt, expiresAt: $expiresAt);

        $this->assertSame(self::VALUE, $entity->getValue());
        $this->assertSame($createdAt, $entity->getCreatedAt());
        $this->assertSame($expiresAt, $entity->getExpirestAt());
        $this->assertFalse($entity->isRevoked());
    }


    public function testIsRevokedWhenStoredSoOrOnceRevoked(): void
    {
        $this->assertTrue($this->sut(isRevoked: true)->isRevoked());

        $entity = $this->sut();
        $entity->revoke();

        $this->assertTrue($entity->isRevoked());
    }


    /**
     * The row as the repository stores it: the two moments in the database's datetime format, and the
     * revocation flag as the boolean it is, which the repository binds as a PDO boolean.
     */
    public function testTheStateIsTheRowTheRepositoryStores(): void
    {
        $entity = $this->sut();
        $row = [
            'value' => self::VALUE,
            'created_at' => self::CREATED_AT,
            'expires_at' => self::EXPIRES_AT,
            'is_revoked' => false,
        ];

        $this->assertSame($row, $entity->getState());

        $entity->revoke();

        $this->assertSame(array_replace($row, ['is_revoked' => true]), $entity->getState());
    }


    /**
     * The moments are written out in the zone they hold, with no conversion. What keeps the columns in
     * UTC is that the factory hands over UTC moments -- from `Helpers::dateTime()->getUtc()` when it mints
     * a new state and when it reads a row back -- and this is the entity's half of that arrangement made
     * explicit.
     */
    public function testWritesTheMomentsInTheZoneTheyHold(): void
    {
        $entity = $this->sut(
            createdAt: $this->moment('2026-09-19 16:00:00', 'Europe/Zagreb'),
            expiresAt: $this->moment('2026-09-19 16:10:00', 'Europe/Zagreb'),
        );

        $state = $entity->getState();

        $this->assertSame('2026-09-19 16:00:00', $state['created_at']);
        $this->assertSame('2026-09-19 16:10:00', $state['expires_at']);
    }
}
