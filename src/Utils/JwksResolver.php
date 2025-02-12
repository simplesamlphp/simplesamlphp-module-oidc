<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils;

use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\OpenID\Jwks;

class JwksResolver
{
    public function __construct(protected Jwks $jwks)
    {
    }

    /**
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     */
    public function forClient(ClientEntityInterface $client): ?array
    {
        if (
            ($signedJwksUri = $client->getSignedJwksUri()) &&
            ($federationJwks = $client->getFederationJwks())
        ) {
            return $this->jwks->jwksFetcher()->fromCacheOrSignedJwksUri(
                $signedJwksUri,
                $federationJwks,
            )?->jsonSerialize();
        }

        if (($jwksUri = $client->getJwksUri())) {
            return $this->jwks->jwksFetcher()->fromCacheOrJwksUri($jwksUri)?->jsonSerialize();
        }

        return $client->getJwks();
    }
}
