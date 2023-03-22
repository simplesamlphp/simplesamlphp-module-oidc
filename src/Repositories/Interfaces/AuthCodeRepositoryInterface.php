<?php

namespace SimpleSAML\Module\oidc\Repositories\Interfaces;

use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface as OAuth2AuthCodeRepositoryInterface;
use SimpleSAML\Module\oidc\Entity\Interfaces\AuthCodeEntityInterface;

interface AuthCodeRepositoryInterface extends OAuth2AuthCodeRepositoryInterface
{
    /**
     * Creates a new AuthCode
     *
     * @return AuthCodeEntityInterface
     */
    public function getNewAuthCode(): AuthCodeEntityInterface;
}
