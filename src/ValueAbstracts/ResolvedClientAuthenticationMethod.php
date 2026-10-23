<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\ValueAbstracts;

use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\OpenID\Codebooks\ClientAuthenticationMethodsEnum;

class ResolvedClientAuthenticationMethod
{
    /**
     * @param bool $isSignedWithAShortRsaKey Whether the client proved itself by a signature of an RSA key shorter
     * than FAPI 2.0 lets sign with (section 5.4.1: 2048 bits), which only a client assertion can be
     * (AuthenticatedOAuth2ClientResolver::forPrivateKeyJwt()). Recorded rather than refused where the signature is
     * verified, since the request which refuses it, an issuance request while issuance follows HAIP, is told apart
     * only afterwards at the PAR endpoint.
     */
    public function __construct(
        protected readonly ClientEntityInterface $client,
        protected readonly ClientAuthenticationMethodsEnum $clientAuthenticationMethod,
        protected readonly bool $isSignedWithAShortRsaKey = false,
    ) {
    }


    public function getClient(): ClientEntityInterface
    {
        return $this->client;
    }


    public function getClientAuthenticationMethod(): ClientAuthenticationMethodsEnum
    {
        return $this->clientAuthenticationMethod;
    }


    public function isSignedWithAShortRsaKey(): bool
    {
        return $this->isSignedWithAShortRsaKey;
    }
}
