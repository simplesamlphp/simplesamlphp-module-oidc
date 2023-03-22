<?php

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

class TimestampGenerator
{
    /**
     * @param string $time
     *
     * @return \DateTime
     */
    public static function utc($time = 'now')
    {
        return new \DateTime($time, new \DateTimeZone('UTC'));
    }
}
