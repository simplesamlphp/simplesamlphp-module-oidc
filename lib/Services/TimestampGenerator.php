<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * (c) Sergio Gómez <sergio@uco.es>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Modules\OpenIDConnect\Services;

class TimestampGenerator
{
    public static function utc($time = 'now')
    {
        return new \DateTimeImmutable($time, new \DateTimeZone('UTC'));
    }
}
