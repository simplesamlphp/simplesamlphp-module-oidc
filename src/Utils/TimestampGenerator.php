<?php

declare(strict_types=1);

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * Copyright (C) 2018 by the Spanish Research and Academic Network.
 *
 * This code was developed by Universidad de Córdoba (UCO https://www.uco.es)
 * for the RedIRIS SIR service (SIR: http://www.rediris.es/sir)
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */
namespace SimpleSAML\Module\oidc\Utils;

use DateTime;
use DateTimeImmutable;
use DateTimeZone;

class TimestampGenerator
{
    /**
     * @throws \Exception
     */
    public static function utc(string $time = 'now'): DateTime
    {
        return new DateTime($time, new DateTimeZone('UTC'));
    }

    /**
     * @throws \Exception
     */
    public static function utcImmutable(string $time = 'now'): DateTimeImmutable
    {
        return DateTimeImmutable::createFromMutable(self::utc($time));
    }
}
