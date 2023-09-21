<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Entity\Interfaces;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface as OAuth2AccessTokenEntityInterface;

interface AccessTokenEntityInterface extends
    OAuth2AccessTokenEntityInterface,
    TokenAssociatableWithAuthCodeInterface,
    TokenRevokableInterface,
    MementoInterface
{
}
