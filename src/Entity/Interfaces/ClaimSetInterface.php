<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Entity\Interfaces;

/**
 * This file contains modified code from the 'steverhoades/oauth2-openid-connect-server' library
 * (https://github.com/steverhoades/oauth2-openid-connect-server), with original author, copyright notice and licence:
 * @author Steve Rhoades <sedonami@gmail.com>
 * @copyright (c) 2018 Steve Rhoades <sedonami@gmail.com>
 * @license http://opensource.org/licenses/MIT MIT
 */
interface ClaimSetInterface
{
    public function getClaims(): array;
}
