<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controller\Federation;

use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\FederationCache;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;
use SimpleSAML\OpenID\Codebooks\EntityTypesEnum;
use SimpleSAML\OpenID\Core;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\Jwks;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;

// TODO mivanci remove controller

/**
 * @psalm-suppress UnevaluatedCode, UnusedVariable, MixedAssignment, MixedArgument, PossiblyNullPropertyFetch,
 * @psalm-suppress PossiblyNullReference, PossiblyUnusedProperty
 */
class Test
{
    public function __construct(
        protected Federation $federation,
        protected ProtocolCache $protocolCache,
        protected FederationCache $federationCache,
        protected LoggerService $loggerService,
        protected Jwks $jwks,
        protected \DateInterval $maxCacheDuration = new \DateInterval('PT30S'),
    ) {
    }

    public function __invoke(): Response
    {

        //$this->protocolCache->set('value', 10, 'test');
        //dd($this->protocolCache, $this->protocolCache->get(null, 'test'));


        $requestObjectFactory = (new Core())->requestObjectFactory();

        // {"alg":"none"}, {"iss":"joe",
        //      "exp":1300819380,
        //      "http://example.com/is_root":true}
        $unprotectedJws = 'eyJhbGciOiJub25lIn0.' .
        'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.';

        $requestObject = $requestObjectFactory->fromToken($unprotectedJws);

//        dd($requestObject, $requestObject->getPayload(), $requestObject->getHeader());
//        $cache->clear();

        $trustChain = $this->federation
            ->trustChainResolver()
//            ->for(
//                'https://08-dap.localhost.markoivancic.from.hr/openid/entities/ALeaf/',
//                [
//                    'https://08-dap.localhost.markoivancic.from.hr/openid/entities/ABTrustAnchor/',
//                    'https://08-dap.localhost.markoivancic.from.hr/openid/entities/CTrustAnchor/',
//                ],
//            );
            ->for(
//                'https://trust-anchor.testbed.oidcfed.incubator.geant.org/oidc/rp/',
//                'https://relying-party-php.testbed.oidcfed.incubator.geant.org/',
//                'https://gorp.testbed.oidcfed.incubator.geant.org',
                'https://maiv1.incubator.geant.org',
                [
                    'https://trust-anchor.testbed.oidcfed.incubator.geant.org/',
                ],
            );

        $leaf = $trustChain->getResolvedLeaf();

        $leafFederationJwks = $leaf->getJwks();

        $resolvedMetadata = $trustChain->getResolvedMetadata(EntityTypesEnum::OpenIdRelyingParty);
        $jwksUri = $resolvedMetadata['jwks_uri'] ?? null;
        $signedJwksUri = $resolvedMetadata['signed_jwks_uri'] ?? null;
        dd($leaf, $leafFederationJwks, $resolvedMetadata, $jwksUri, $signedJwksUri);
        $cachedJwks = $jwksUri ? $this->jwks->jwksFetcher()->fromCache($jwksUri) : null;
        $jwks = $jwksUri ? $this->jwks->jwksFetcher()->fromJwksUri($jwksUri) : null;

        $cachedSignedJwks = $signedJwksUri ? $this->jwks->jwksFetcher()->fromCache($signedJwksUri) : null;
        $signedJwks = $signedJwksUri ? $this->jwks->jwksFetcher()
            ->fromSignedJwksUri($signedJwksUri, $leafFederationJwks) : null;
        dd(
            $signedJwksUri,
            $cachedSignedJwks,
            $signedJwks,
        );

        return new JsonResponse(
            $trustChain->getResolvedMetadata(EntityTypesEnum::OpenIdRelyingParty),
        );
    }
}
