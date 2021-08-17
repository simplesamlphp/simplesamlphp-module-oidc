<?php

namespace SimpleSAML\Module\oidc\Repositories\Interfaces;

use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use SimpleSAML\Module\oidc\Entity\Interfaces\OidcAuthCodeEntityInterface;

interface OidcAuthCodeRepositoryInterface extends AuthCodeRepositoryInterface
{
    /**
     * Creates a new AuthCode
     *
     * @return OidcAuthCodeEntityInterface
     */
    public function getNewAuthCode(): OidcAuthCodeEntityInterface;
}
