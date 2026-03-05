<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\ValueAbstracts;

use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\OpenID\Codebooks\ClientAuthenticationMethodsEnum;

class ResolvedClientAuthenticationMethod
{
    public function __construct(
        protected readonly ClientEntityInterface $client,
        protected readonly ClientAuthenticationMethodsEnum $clientAuthenticationMethod,
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
}
