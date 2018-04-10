<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * (c) Sergio Gómez <sergio@uco.es>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Modules\OpenIDConnect\Factories;

use SimpleSAML\Auth\Simple;

class AuthSimpleFactory
{
    /**
     * @codeCoverageIgnore
     */
    public function build(string $name): Simple
    {
        return new Simple($name);
    }
}
