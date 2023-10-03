<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Entities\Interfaces;

use League\OAuth2\Server\Entities\RefreshTokenEntityInterface as OAuth2RefreshTokenEntityInterface;

interface RefreshTokenEntityInterface extends
    OAuth2RefreshTokenEntityInterface,
    TokenAssociatableWithAuthCodeInterface,
    TokenRevokableInterface,
    MementoInterface
{
}
