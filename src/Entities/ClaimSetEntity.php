<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Entities;

use SimpleSAML\Module\oidc\Entities\Interfaces\ClaimSetEntityInterface;

/**
 * This file contains modified code from the 'steverhoades/oauth2-openid-connect-server' library
 * (https://github.com/steverhoades/oauth2-openid-connect-server), with original author, copyright notice and licence:
 * @author Steve Rhoades <sedonami@gmail.com>
 * @copyright (c) 2018 Steve Rhoades <sedonami@gmail.com>
 * @license http://opensource.org/licenses/MIT MIT
 */
class ClaimSetEntity implements ClaimSetEntityInterface
{
    public function __construct(protected string $scope, protected array $claims)
    {
    }

    public function getScope(): string
    {
        return $this->scope;
    }

    public function getClaims(): array
    {
        return $this->claims;
    }
}
