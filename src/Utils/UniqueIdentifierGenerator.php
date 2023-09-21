<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils;

use League\OAuth2\Server\Exception\OAuthServerException;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use Throwable;

class UniqueIdentifierGenerator
{
    /**
     * Generate a new unique identifier.
     *
     * @throws OAuthServerException
     */
    public static function hitMe(int $length = 40): string
    {
        if ($length < 1) {
            throw OidcServerException::serverError('Random string lenght can not be less than 1');
        }

        try {
            return bin2hex(random_bytes($length));
        } catch (Throwable $e) {
            throw OidcServerException::serverError('Could not generate a random string', $e);
        }
    }
}
