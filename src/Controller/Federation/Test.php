<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controller\Federation;

use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\FederationCache;
use SimpleSAML\OpenID\Codebooks\EntityTypesEnum;
use SimpleSAML\OpenID\Core;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\Jwks;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;

// TODO mivanci remove controller

/**
 * @psalm-suppress UnevaluatedCode, UnusedVariable, MixedAssignment, MixedArgument, PossiblyNullPropertyFetch,
 * @psalm-suppress PossiblyNullReference
 */
class Test
{
    public function __construct(
        protected FederationCache $federationCache,
        protected LoggerService $loggerService,
        protected Jwks $jwks,
        protected \DateInterval $maxCacheDuration = new \DateInterval('PT30S'),
    ) {
    }

    public function __invoke(): Response
    {

//        $cache = new Psr16Cache(new FilesystemAdapter(
//            'oidc-federation',
//            60,
//            $this->moduleConfig->sspConfig()->getPathValue('cachedir'),
//        ));

        $requestObjectFactory = (new Core())->requestObjectFactory();

        // {"alg":"none"}, {"iss":"joe",
        //      "exp":1300819380,
        //      "http://example.com/is_root":true}
        $unprotectedJws = 'eyJhbGciOiJub25lIn0.' .
        'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.';

        $requestObject = $requestObjectFactory->fromToken($unprotectedJws);

//        dd($requestObject, $requestObject->getPayload(), $requestObject->getHeader());
//        $cache->clear();

        $trustChain = (new Federation(
            maxCacheDuration: $this->maxCacheDuration,
            cache: $this->federationCache->cache,
            logger: $this->loggerService,
        ))
            ->trustChainResolver()
            ->for(
                'https://08-dap.localhost.markoivancic.from.hr/openid/entities/ALeaf/',
                [
                    'https://08-dap.localhost.markoivancic.from.hr/openid/entities/ABTrustAnchor/',
                    'https://08-dap.localhost.markoivancic.from.hr/openid/entities/CTrustAnchor/',
                ],
            );

        $leaf = $trustChain->getResolvedLeaf();

        $leafFederationJwks = $leaf->getJwks();

        $resolvedMetadata = $trustChain->getResolvedMetadata(EntityTypesEnum::OpenIdRelyingParty);
        $jwksUri = $resolvedMetadata['jwks_uri'] ?? null;
        $signedJwksUri = $resolvedMetadata['signed_jwks_uri'] ?? null;

        $cachedJwks = $jwksUri ? $this->jwks->jwksFetcher()->fromCache($jwksUri) : null;
        $jwks = $jwksUri ? $this->jwks->jwksFetcher()->fromJwksUri($jwksUri) : null;

        $cachedSignedJwks = $signedJwksUri ? $this->jwks->jwksFetcher()->fromCache($signedJwksUri) : null;
        $signedJwks = $signedJwksUri ? $this->jwks->jwksFetcher()
            ->fromSignedJwksUri($signedJwksUri, $leafFederationJwks) : null;
        var_export(json_decode(json_encode($jwks->jwks?->jsonSerialize()), true));
        dd(
            var_export(json_decode(json_encode($jwks->jwks->jsonSerialize()), true)),
            $cachedJwks?->jsonSerialize(),
            $signedJwks->jwks->jsonSerialize(),
            $cachedSignedJwks?->jsonSerialize(),
        );

        return new JsonResponse(
            $trustChain->getResolvedMetadata(EntityTypesEnum::OpenIdRelyingParty),
        );
    }
}
