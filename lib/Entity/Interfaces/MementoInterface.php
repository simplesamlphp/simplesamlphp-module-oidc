<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * (c) Sergio Gómez <sergio@uco.es>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Modules\OpenIDConnect\Entity\Interfaces;

interface MementoInterface
{
    /**
     * @param array $state
     *
     * @return self
     */
    public static function fromState(array $state);

    /**
     * @return array
     */
    public function getState(): array;
}
