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
        return $this->getUtc()->setTimestamp($timestamp);
    }

    public function getSecondsToExpirationTime(int $expirationTime): int
    {
        return $expirationTime - $this->getUtc()->getTimestamp();
    }
}
