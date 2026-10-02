<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Helpers;

use DateInterval;
use DateTimeImmutable;
use DateTimeZone;
use InvalidArgumentException;

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


    /**
     * The moment rounded down to a whole multiple of the granularity since the Unix epoch, so to a UTC
     * boundary whatever the moment's timezone, which is kept. Counted in whole seconds, the precision of a
     * JWT time claim, so the result carries no fraction of a second. A granularity of no time leaves the
     * moment as it is, fraction included.
     *
     * @throws \InvalidArgumentException For a granularity in months or years.
     */
    public function floorTo(DateTimeImmutable $moment, DateInterval $granularity): DateTimeImmutable
    {
        $seconds = $this->granularityInSeconds($granularity);
        if ($seconds === 0) {
            return $moment;
        }

        $timestamp = $moment->getTimestamp();

        return $moment->setTimestamp($timestamp - $this->remainder($timestamp, $seconds));
    }


    /**
     * The moment rounded up to a whole multiple of the granularity since the Unix epoch, the counterpart
     * of floorTo(). A moment on a boundary stays on it, while one a fraction of a second past a boundary is
     * past it and goes to the next. A granularity of no time leaves the moment as it is.
     *
     * @throws \InvalidArgumentException For a granularity in months or years.
     */
    public function ceilTo(DateTimeImmutable $moment, DateInterval $granularity): DateTimeImmutable
    {
        $seconds = $this->granularityInSeconds($granularity);
        if ($seconds === 0) {
            return $moment;
        }

        // getTimestamp() drops the fraction, which would round a moment just past a boundary down onto it.
        $timestamp = $moment->getTimestamp() + ($moment->format('u') === '000000' ? 0 : 1);
        $remainder = $this->remainder($timestamp, $seconds);

        return $moment->setTimestamp($remainder === 0 ? $timestamp : $timestamp - $remainder + $seconds);
    }


    /**
     * @throws \InvalidArgumentException
     */
    protected function granularityInSeconds(DateInterval $granularity): int
    {
        if ($granularity->y !== 0 || $granularity->m !== 0) {
            throw new InvalidArgumentException('A month or a year has no fixed length to round on.');
        }

        // DateInterval keeps each field as it was given (PT90M has 90 minutes, P1W has 7 days), so the
        // fields add up to the length whatever their size.
        return $granularity->d * 86400 + $granularity->h * 3600 + $granularity->i * 60 + $granularity->s;
    }


    /**
     * The remainder counted forward from the boundary below, which `%` alone does not give for a moment
     * before the epoch.
     */
    protected function remainder(int $timestamp, int $seconds): int
    {
        return (($timestamp % $seconds) + $seconds) % $seconds;
    }
}
