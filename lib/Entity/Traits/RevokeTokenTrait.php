<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * (c) Sergio Gómez <sergio@uco.es>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Modules\OpenIDConnect\Entity\Traits;

trait RevokeTokenTrait
{
    /**
     * @var bool
     */
    protected $isRevoked = 0;

    /**
     * @return bool
     */
    public function isRevoked(): bool
    {
        return (bool) $this->isRevoked;
    }

    /**
     * Revoke token.
     */
    public function revoke()
    {
        $this->isRevoked = 1;
    }
}
