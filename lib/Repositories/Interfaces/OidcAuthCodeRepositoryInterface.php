<?php

namespace SimpleSAML\Modules\OpenIDConnect\Repositories\Interfaces;

use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use SimpleSAML\Modules\OpenIDConnect\Entity\Interfaces\OidcAuthCodeEntityInterface;

interface OidcAuthCodeRepositoryInterface extends AuthCodeRepositoryInterface
{
    /**
     * Creates a new AuthCode
     *
     * @return OidcAuthCodeEntityInterface
     */
    public function getNewAuthCode();
}
