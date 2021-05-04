<?php

namespace SimpleSAML\Modules\OpenIDConnect\Server\Exceptions;

use League\OAuth2\Server\Exception\OAuthServerException;

class OidcServerException extends OAuthServerException
{
    /**
     * Unsupported response type error.
     *
     * @param null $redirectUri
     * @return self
     */
    public static function unsupportedResponseType($redirectUri = null): OidcServerException
    {
        $errorMessage = 'The response type is not supported by the authorization server.';
        $hint = 'Check that all required parameters have been provided';

        return new self($errorMessage, 2, 'unsupported_response_type', 400, $hint, $redirectUri);
    }
}
