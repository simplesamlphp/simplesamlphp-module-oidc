<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Helpers;

use DateTimeImmutable;
use DateTimeZone;

class DateTime
{
    public function getUtc(string $time = 'now'): DateTimeImmutable
    {
        return new DateTimeImmutable($time, new DateTimeZone('UTC'));
    }

    public function getFromTimestamp(int $timestamp): DateTimeImmutable
    {
        return (new DateTimeImmutable())->setTimestamp($timestamp);
    }
}
