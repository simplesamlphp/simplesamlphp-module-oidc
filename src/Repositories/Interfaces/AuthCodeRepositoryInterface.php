<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Repositories\Interfaces;

use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface as OAuth2AuthCodeRepositoryInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\AuthCodeEntityInterface;

interface AuthCodeRepositoryInterface extends OAuth2AuthCodeRepositoryInterface
{
    /**
     * Creates a new AuthCode
     */
    public function getNewAuthCode(): AuthCodeEntityInterface;
}
