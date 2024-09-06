<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Helpers;

use DateTimeImmutable;
use DateTimeZone;

class DateTime
{
    public function getTimestamp(string $time = 'now'): DateTimeImmutable
    {
        return new DateTimeImmutable($time, new DateTimeZone('UTC'));
    }
}
