<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils;

use DateInterval;

/**
 * Renders DateInterval instances in forms suitable for the admin UI.
 *
 * A DateInterval created from a duration spec is not normalized (PT48H stays 48 hours, it does not
 * become 2 days), so every component is rendered exactly as it was configured. Zero components are
 * omitted, which keeps common values like PT10M readable.
 */
class DateIntervalFormatter
{
    /**
     * Render the interval as a human readable string, for example, '10 minutes'.
     */
    public function toHumanReadable(DateInterval $dateInterval): string
    {
        $parts = [];

        $components = [
            [$dateInterval->y, 'year', 'years'],
            [$dateInterval->m, 'month', 'months'],
            [$dateInterval->d, 'day', 'days'],
            [$dateInterval->h, 'hour', 'hours'],
            [$dateInterval->i, 'minute', 'minutes'],
            [$dateInterval->s, 'second', 'seconds'],
        ];

        foreach ($components as [$amount, $singular, $plural]) {
            if ($amount === 0) {
                continue;
            }

            $parts[] = $amount . ' ' . ($amount === 1 ? $singular : $plural);
        }

        return $parts === [] ? '0 seconds' : implode(' ', $parts);
    }


    /**
     * Render the interval back to its ISO 8601 duration spec, that is, the form used in the module
     * configuration file, for example, 'PT10M'. Handy on overview screens, since it is the value an
     * administrator has to edit in order to change the setting.
     */
    public function toDurationSpec(DateInterval $dateInterval): string
    {
        $datePart = ($dateInterval->y > 0 ? $dateInterval->y . 'Y' : '') .
        ($dateInterval->m > 0 ? $dateInterval->m . 'M' : '') .
        ($dateInterval->d > 0 ? $dateInterval->d . 'D' : '');

        $timePart = ($dateInterval->h > 0 ? $dateInterval->h . 'H' : '') .
        ($dateInterval->i > 0 ? $dateInterval->i . 'M' : '') .
        ($dateInterval->s > 0 ? $dateInterval->s . 'S' : '');

        if ($datePart === '' && $timePart === '') {
            return 'PT0S';
        }

        return 'P' . $datePart . ($timePart === '' ? '' : 'T' . $timePart);
    }
}
