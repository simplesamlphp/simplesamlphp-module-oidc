<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Entities;

use DateTimeImmutable;
use DateTimeZone;
use JsonException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Entities\PushedAuthorizationRequestEntity;

/**
 * A Pushed Authorization Request once it has been accepted: the `request_uri` it was given, the client it
 * came from, the authorization parameters it carried, the moment it stops being usable, and whether it has
 * been used.
 *
 * Its factory is the only thing in `src/` which constructs one -- from a fresh request, and from a stored
 * row -- and the repository stores `getState()` as the row. Whether it is still usable is asked in two
 * places, the repository's `findValid()` and the `request_uri` rule, both with the current UTC moment.
 * Consumption is another matter: the repository marks a request consumed with a conditional UPDATE on the
 * row, so `consume()` here has no caller in `src/`, and `isConsumed()` reports what the row said.
 */
#[CoversClass(PushedAuthorizationRequestEntity::class)]
class PushedAuthorizationRequestEntityTest extends TestCase
{
    protected const string REQUEST_URI = 'urn:ietf:params:oauth:request_uri:5f4dcc3b5aa765d61d8327deb882cf99';

    protected const string CLIENT_ID = 'client-a1b2c3';

    protected const array PARAMETERS = [
        'response_type' => 'code',
        'redirect_uri' => 'https://rp.example.org/cb',
        'scope' => 'openid profile',
    ];

    protected const string EXPIRES_AT = '2026-09-19 14:30:00';


    protected function moment(string $moment, string $timezone = 'UTC'): DateTimeImmutable
    {
        return new DateTimeImmutable($moment, new DateTimeZone($timezone));
    }


    /**
     * @param array<string,mixed> $parameters
     */
    protected function sut(
        bool $isConsumed = false,
        ?DateTimeImmutable $expiresAt = null,
        array $parameters = self::PARAMETERS,
    ): PushedAuthorizationRequestEntity {
        return new PushedAuthorizationRequestEntity(
            self::REQUEST_URI,
            self::CLIENT_ID,
            $parameters,
            $expiresAt ?? $this->moment(self::EXPIRES_AT),
            $isConsumed,
        );
    }


    public function testCarriesWhatItWasGiven(): void
    {
        $expiresAt = $this->moment(self::EXPIRES_AT);

        $entity = $this->sut(expiresAt: $expiresAt);

        $this->assertSame(self::REQUEST_URI, $entity->getRequestUri());
        $this->assertSame(self::CLIENT_ID, $entity->getClientId());
        $this->assertSame(self::PARAMETERS, $entity->getParameters());
        $this->assertSame($expiresAt, $entity->getExpiresAt());
        $this->assertFalse($entity->isConsumed());
    }


    public function testIsConsumedWhenStoredSoOrOnceConsumed(): void
    {
        $this->assertTrue($this->sut(isConsumed: true)->isConsumed());

        $entity = $this->sut();
        $entity->consume();

        $this->assertTrue($entity->isConsumed());
    }


    /**
     * Expiry is exclusive: a request whose lifetime ends at this very second is still usable, and the
     * moment is compared as an instant, so the zone of the moment it is asked with makes no difference.
     */
    #[DataProvider('momentProvider')]
    public function testIsExpiredOnlyOnceItsMomentHasPassed(string $now, string $timezone, bool $expected): void
    {
        $this->assertSame($expected, $this->sut()->isExpired($this->moment($now, $timezone)));
    }


    /**
     * @return array<string,array{string,string,bool}>
     */
    public static function momentProvider(): array
    {
        return [
            'one second before' => ['2026-09-19 14:29:59', 'UTC', false],
            'the very second' => ['2026-09-19 14:30:00', 'UTC', false],
            'one second after' => ['2026-09-19 14:30:01', 'UTC', true],
            'the very second, in another zone' => ['2026-09-19 16:30:00', 'Europe/Zagreb', false],
        ];
    }


    /**
     * The row as the repository stores it. The parameters go in as one JSON document, slashes escaped as
     * PHP's encoder does by default, which the factory's decode reverses; the moment goes in as the
     * database's datetime format; the consumption flag goes in as the boolean it is, which the repository
     * casts to an integer for the INSERT.
     *
     * @throws \JsonException
     */
    public function testTheStateIsTheRowTheRepositoryStores(): void
    {
        $entity = $this->sut();
        $row = [
            'request_uri' => self::REQUEST_URI,
            'client_id' => self::CLIENT_ID,
            'parameters' => '{"response_type":"code","redirect_uri":"https:\/\/rp.example.org\/cb",' .
                '"scope":"openid profile"}',
            'expires_at' => self::EXPIRES_AT,
            'is_consumed' => false,
        ];

        $this->assertSame($row, $entity->getState());

        $entity->consume();

        $this->assertSame(array_replace($row, ['is_consumed' => true]), $entity->getState());
    }


    /**
     * The moment is written out in the zone it holds, with no conversion. What keeps the column in UTC is
     * that the factory hands over UTC moments -- from `Helpers::dateTime()->getUtc()` on both of its paths
     * -- and this is the entity's half of that arrangement made explicit.
     *
     * @throws \JsonException
     */
    public function testWritesTheExpiryInTheZoneOfTheMomentItHolds(): void
    {
        $entity = $this->sut(expiresAt: $this->moment('2026-09-19 16:30:00', 'Europe/Zagreb'));

        $this->assertSame('2026-09-19 16:30:00', $entity->getState()['expires_at']);
    }


    /**
     * A parameter value which is not UTF-8 has no JSON form. The encoder is told to throw, so the state
     * raises rather than come back with the parameters missing and let a row without them be stored.
     *
     * @throws \JsonException
     */
    public function testRefusesToStateParametersWhichHaveNoJsonForm(): void
    {
        $entity = $this->sut(parameters: ['login_hint' => "\xB1\x31"]);

        $this->expectException(JsonException::class);

        $entity->getState();
    }
}
