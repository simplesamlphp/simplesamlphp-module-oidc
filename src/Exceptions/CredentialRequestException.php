<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Exceptions;

/**
 * A Credential Request this issuer refuses, carrying the error code the wallet is answered with.
 *
 * OpenID4VCI does not answer every refusal with the same code, and the difference is actionable for the
 * wallet: one told `invalid_nonce` asks the Nonce Endpoint for a fresh nonce and retries, while one told
 * `invalid_proof` has to fix the proof itself instead. Carrying the code on the exception keeps the
 * choice with the check that made it, rather than flattening every refusal to one code at the boundary.
 *
 * The message is returned to the wallet as `error_description`, so it says what is wrong with the
 * request without repeating back anything the request itself supplied.
 */
class CredentialRequestException extends OidcException
{
    /**
     * @param non-empty-string $errorCode The OpenID4VCI error code, for example `invalid_proof`.
     */
    public function __construct(
        protected readonly string $errorCode,
        string $message,
    ) {
        parent::__construct($message);
    }


    /**
     * @return non-empty-string
     */
    public function getErrorCode(): string
    {
        return $this->errorCode;
    }
}
