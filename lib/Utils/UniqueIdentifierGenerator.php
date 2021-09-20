<?php

namespace SimpleSAML\Module\oidc\Utils;

use League\OAuth2\Server\Exception\OAuthServerException;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;

class UniqueIdentifierGenerator
{
    /**
     * Generate a new unique identifier.
     *
     * @param int $length
     * @return string
     * @throws OAuthServerException
     */
    public static function hitMe(int $length = 40)
    {
        try {
            return \bin2hex(\random_bytes($length));
        } catch (\Throwable $e) {
            throw OidcServerException::serverError('Could not generate a random string', $e);
        }
    }
}
