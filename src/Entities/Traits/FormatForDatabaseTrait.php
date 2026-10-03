<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Entities\Traits;

use DateTimeImmutable;
use DateTimeZone;
use SimpleSAML\Module\oidc\Codebooks\DateFormatsEnum;

trait FormatForDatabaseTrait
{
    /**
     * Stored moments are written without a zone and read back as UTC, so a moment is converted to UTC on the
     * way in rather than having its wall clock written as-is. The expiry of a code or token is made in PHP's
     * default time zone; written as that zone's wall clock, it would be read back shifted by the zone's offset,
     * and on a server west of UTC a code just issued would read as already expired.
     */
    protected function formatForDatabase(DateTimeImmutable $moment): string
    {
        return $moment->setTimezone(new DateTimeZone('UTC'))->format(DateFormatsEnum::DB_DATETIME->value);
    }
}
