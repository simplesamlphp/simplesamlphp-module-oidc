<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\ValueAbstracts;

/**
 * Who an API request is made by, and which credential configurations it may act on.
 *
 * @see \SimpleSAML\Module\oidc\Services\Api\Authorization::requireBearerTokenForAnyOfScope()
 */
class ApiCaller
{
    /**
     * @param string $principal Who the caller stands for, for recording against what it changes. Never an API
     * token itself.
     */
    public function __construct(
        protected readonly string $principal,
        protected readonly CredentialConfigurationLimit $credentialConfigurationLimit,
    ) {
    }


    public function getPrincipal(): string
    {
        return $this->principal;
    }


    public function getCredentialConfigurationLimit(): CredentialConfigurationLimit
    {
        return $this->credentialConfigurationLimit;
    }
}
