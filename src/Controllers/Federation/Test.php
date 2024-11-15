<?php

// phpcs:ignoreFile

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers\Federation;

use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Codebooks\RegistrationTypeEnum;
use SimpleSAML\Module\oidc\Factories\CoreFactory;
use SimpleSAML\Module\oidc\Factories\Entities\ClientEntityFactory;
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
 * @psalm-suppress UnevaluatedCode, UnusedVariable, MixedAssignment, MixedArgument, PossiblyNullPropertyFetch, PossiblyNullArgument
 * @psalm-suppress PossiblyNullReference, PossiblyUnusedProperty, PossiblyNullArgument
 */
class Test
{
    public function __construct(
        protected Federation $federation,
        protected ?ProtocolCache $protocolCache,
        protected ?FederationCache $federationCache,
        protected LoggerService $loggerService,
        protected Jwks $jwks,
        protected Database $database,
        protected ClientEntityFactory $clientEntityFactory,
        protected CoreFactory $coreFactory,
        protected \DateInterval $maxCacheDuration = new \DateInterval('PT30S'),
    ) {
    }

    public function __invoke(): Response
    {
//        dd($this->coreFactory->build());
//        $t = 'eyJ0eXAiOiJlbnRpdHktc3RhdGVtZW50K2p3dCIsImFsZyI6IlJTMjU2Iiwia2lkIjoiYzRhZmYzY2M3NDM5MWI3M2UxM2FhODE2OTdkYmYzODIifQ.eyJpc3MiOiJodHRwczovLzgyLWRhcC5sb2NhbGhvc3QubWFya29pdmFuY2ljLmZyb20uaHIiLCJpYXQiOjE3MjY4NTM0NTUsImp0aSI6IjQ0ZDQyNDQxOGIyZDEwOWY4M2FhNDMzY2Y0YTVhODNiMTI4YjgzZDZiZDExOTRjMDI1NTgzMTQ1YmZkMjNjMzZjZDg1Y2UzMzBjN2ZlOTc4Iiwic3ViIjoiaHR0cHM6Ly84Mi1kYXAubG9jYWxob3N0Lm1hcmtvaXZhbmNpYy5mcm9tLmhyIiwiZXhwIjoxNzI2OTM5ODU1LCJqd2tzIjp7ImtleXMiOlt7Imt0eSI6IlJTQSIsIm4iOiJzTHpnc0NiaW40Y0l1YUlFZ0w3QzBvaXZSazNyN09HSTBUdWJ0TFBYMkJiMmI5QmtPVElUcnhqSjIwenVVblVLbUJ5eGdyaFJUZGtVWW9EcFJOenVIUENyeVdwU0NQSDB5SUZPUVdxbEFxWHEzXzJheHcwTzlCMFVYVzYzQWNaRVBERVlVWGFsNHNaazE3OG9ZMTNhUlk0Um9NZm8yZkZ1cDlyb2RpSFJqU0gweWsxS2tEOWR5NjZGM1ZmaTF6SHRGQzhkV000clE5cW1OS3pyVFpXMzFsVmQ3N3ZvajZsNE1BOFlYWFVuM2dVMHRocUxMRFI3WnhJcFdUcU1VbzVDRXFJZ0pZS0FRUG5sZldvQ2JiMVhWSl9qMFNQZzZ0M29GNTUwNGd3SFp3M1dDSHJEbUxzdTdpa29CcmdrRWZnS05ISWlra3hXalB0bGNmbmlXUjl2b1EiLCJlIjoiQVFBQiIsImtpZCI6ImM0YWZmM2NjNzQzOTFiNzNlMTNhYTgxNjk3ZGJmMzgyIiwidXNlIjoic2lnIiwiYWxnIjoiUlMyNTYifV19LCJtZXRhZGF0YSI6eyJmZWRlcmF0aW9uX2VudGl0eSI6eyJvcmdhbml6YXRpb25fbmFtZSI6IkZvbyBjb3JwIiwiY29udGFjdHMiOlsiSm9obiBEb2UgamRvZUBleGFtcGxlLm9yZyJdLCJsb2dvX3VyaSI6Imh0dHBzOi8vZXhhbXBsZS5vcmcvbG9nbyIsInBvbGljeV91cmkiOiJodHRwczovL2V4YW1wbGUub3JnL3BvbGljeSIsImhvbWVwYWdlX3VyaSI6Imh0dHBzOi8vZXhhbXBsZS5vcmciLCJmZWRlcmF0aW9uX2ZldGNoX2VuZHBvaW50IjoiaHR0cHM6Ly84Mi1kYXAubG9jYWxob3N0Lm1hcmtvaXZhbmNpYy5mcm9tLmhyL3NpbXBsZXNhbWxwaHAvc2ltcGxlc2FtbHBocC0yLjIvbW9kdWxlLnBocC9vaWRjL2ZlZGVyYXRpb24vZmV0Y2gifSwib3BlbmlkX3Byb3ZpZGVyIjp7Imlzc3VlciI6Imh0dHBzOi8vODItZGFwLmxvY2FsaG9zdC5tYXJrb2l2YW5jaWMuZnJvbS5ociIsImF1dGhvcml6YXRpb25fZW5kcG9pbnQiOiJodHRwczovLzgyLWRhcC5sb2NhbGhvc3QubWFya29pdmFuY2ljLmZyb20uaHIvc2ltcGxlc2FtbHBocC9zaW1wbGVzYW1scGhwLTIuMi9tb2R1bGUucGhwL29pZGMvYXV0aG9yaXphdGlvbiIsInRva2VuX2VuZHBvaW50IjoiaHR0cHM6Ly84Mi1kYXAubG9jYWxob3N0Lm1hcmtvaXZhbmNpYy5mcm9tLmhyL3NpbXBsZXNhbWxwaHAvc2ltcGxlc2FtbHBocC0yLjIvbW9kdWxlLnBocC9vaWRjL3Rva2VuIiwidXNlcmluZm9fZW5kcG9pbnQiOiJodHRwczovLzgyLWRhcC5sb2NhbGhvc3QubWFya29pdmFuY2ljLmZyb20uaHIvc2ltcGxlc2FtbHBocC9zaW1wbGVzYW1scGhwLTIuMi9tb2R1bGUucGhwL29pZGMvdXNlcmluZm8iLCJlbmRfc2Vzc2lvbl9lbmRwb2ludCI6Imh0dHBzOi8vODItZGFwLmxvY2FsaG9zdC5tYXJrb2l2YW5jaWMuZnJvbS5oci9zaW1wbGVzYW1scGhwL3NpbXBsZXNhbWxwaHAtMi4yL21vZHVsZS5waHAvb2lkYy9lbmQtc2Vzc2lvbiIsImp3a3NfdXJpIjoiaHR0cHM6Ly84Mi1kYXAubG9jYWxob3N0Lm1hcmtvaXZhbmNpYy5mcm9tLmhyL3NpbXBsZXNhbWxwaHAvc2ltcGxlc2FtbHBocC0yLjIvbW9kdWxlLnBocC9vaWRjL2p3a3MiLCJzY29wZXNfc3VwcG9ydGVkIjpbIm9wZW5pZCIsIm9mZmxpbmVfYWNjZXNzIiwicHJvZmlsZSIsImVtYWlsIiwiYWRkcmVzcyIsInBob25lIiwiaHJFZHVQZXJzb25VbmlxdWVJRCIsInVpZCIsImNuIiwic24iLCJnaXZlbk5hbWUiLCJtYWlsIiwidGVsZXBob25lTnVtYmVyIiwiaHJFZHVQZXJzb25FeHRlbnNpb25OdW1iZXIiLCJtb2JpbGUiLCJmYWNzaW1pbGVUZWxlcGhvbmVOdW1iZXIiLCJockVkdVBlcnNvblVuaXF1ZU51bWJlciIsImhyRWR1UGVyc29uT0lCIiwiaHJFZHVQZXJzb25EYXRlT2ZCaXJ0aCIsImhyRWR1UGVyc29uR2VuZGVyIiwianBlZ1Bob3RvIiwidXNlckNlcnRpZmljYXRlIiwibGFiZWxlZFVSSSIsImhyRWR1UGVyc29uUHJvZmVzc2lvbmFsU3RhdHVzIiwiaHJFZHVQZXJzb25BY2FkZW1pY1N0YXR1cyIsImhyRWR1UGVyc29uU2NpZW5jZUFyZWEiLCJockVkdVBlcnNvbkFmZmlsaWF0aW9uIiwiaHJFZHVQZXJzb25QcmltYXJ5QWZmaWxpYXRpb24iLCJockVkdVBlcnNvblN0dWRlbnRDYXRlZ29yeSIsImhyRWR1UGVyc29uRXhwaXJlRGF0ZSIsImhyRWR1UGVyc29uVGl0bGUiLCJockVkdVBlcnNvblJvbGUiLCJockVkdVBlcnNvblN0YWZmQ2F0ZWdvcnkiLCJockVkdVBlcnNvbkdyb3VwTWVtYmVyIiwibyIsImhyRWR1UGVyc29uSG9tZU9yZyIsIm91Iiwicm9vbU51bWJlciIsInBvc3RhbEFkZHJlc3MiLCJsIiwicG9zdGFsQ29kZSIsInN0cmVldCIsImhvbWVQb3N0YWxBZGRyZXNzIiwiaG9tZVRlbGVwaG9uZU51bWJlciIsImhyRWR1UGVyc29uQ29tbVVSSSIsImhyRWR1UGVyc29uUHJpdmFjeSIsImhyRWR1UGVyc29uUGVyc2lzdGVudElEIiwiZGlzcGxheU5hbWUiLCJzY2hhY1VzZXJQcmVzZW5jZUlEIiwiaHJFZHVQZXJzb25DYXJkTnVtIiwiZm9ybWF0ZWRUZXN0Il0sInJlc3BvbnNlX3R5cGVzX3N1cHBvcnRlZCI6WyJjb2RlIiwidG9rZW4iLCJpZF90b2tlbiIsImlkX3Rva2VuIHRva2VuIl0sInN1YmplY3RfdHlwZXNfc3VwcG9ydGVkIjpbInB1YmxpYyJdLCJpZF90b2tlbl9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIlJTMjU2Il0sImNvZGVfY2hhbGxlbmdlX21ldGhvZHNfc3VwcG9ydGVkIjpbInBsYWluIiwiUzI1NiJdLCJ0b2tlbl9lbmRwb2ludF9hdXRoX21ldGhvZHNfc3VwcG9ydGVkIjpbImNsaWVudF9zZWNyZXRfcG9zdCIsImNsaWVudF9zZWNyZXRfYmFzaWMiLCJwcml2YXRlX2tleV9qd3QiXSwicmVxdWVzdF9wYXJhbWV0ZXJfc3VwcG9ydGVkIjp0cnVlLCJyZXF1ZXN0X29iamVjdF9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIm5vbmUiLCJSUzI1NiJdLCJyZXF1ZXN0X3VyaV9wYXJhbWV0ZXJfc3VwcG9ydGVkIjpmYWxzZSwiZ3JhbnRfdHlwZXNfc3VwcG9ydGVkIjpbImF1dGhvcml6YXRpb25fY29kZSIsInJlZnJlc2hfdG9rZW4iXSwiY2xhaW1zX3BhcmFtZXRlcl9zdXBwb3J0ZWQiOnRydWUsImFjcl92YWx1ZXNfc3VwcG9ydGVkIjpbIjEiLCIwIl0sImJhY2tjaGFubmVsX2xvZ291dF9zdXBwb3J0ZWQiOnRydWUsImJhY2tjaGFubmVsX2xvZ291dF9zZXNzaW9uX3N1cHBvcnRlZCI6dHJ1ZSwiY2xpZW50X3JlZ2lzdHJhdGlvbl90eXBlc19zdXBwb3J0ZWQiOlsiYXV0b21hdGljIl0sInJlcXVlc3RfYXV0aGVudGljYXRpb25fbWV0aG9kc19zdXBwb3J0ZWQiOnsiYXV0aG9yaXphdGlvbl9lbmRwb2ludCI6WyJyZXF1ZXN0X29iamVjdCJdfSwicmVxdWVzdF9hdXRoZW50aWNhdGlvbl9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIlJTMjU2Il19fSwiYXV0aG9yaXR5X2hpbnRzIjpbImh0dHBzOi8vZWR1Z2Fpbi5vcmcvIiwiaHR0cHM6Ly84Mi1kYXAubG9jYWxob3N0Lm1hcmtvaXZhbmNpYy5mcm9tLmhyL3NpbXBsZXNhbWxwaHAvc2ltcGxlc2FtbHBocC0yLjIvbW9kdWxlLnBocC9vaWRjLyJdfQ.QOC5hPVzoGe5jJ4o_TkYMyRPWyd7HxqD4flduSAKhF1MIVRkBxgDfV3G1obJd875MsCq_Syb9wZfTP544-nY0z6ulSZm1L08ymzSlWwltcDW-l8rSjuCXErX5UDFNzBwc8ht7F7FfWpNCHrn6-A6t-m5E588IueGZfCqQrKUHRzsObQ8ZCNCkU_hjXgkM-FyERu2_Dnle9wpQ1GszOpNAJAuyMUfissgkokBRrXWwvDbj_7yA8prhgoLhOqtqf_ljMXlx_RggWknd-3zqvBi3U3msHwNnBCQ25E_TH7V_2onASfVOjr2TxyZ5diSkBqoSU9Vqr3bmH3cmcFodu_mvg';
//        $es = $this->federation->entityStatementFetcher()->fromNetwork('https://82-dap.localhost.markoivancic.from.hr/simplesamlphp/simplesamlphp-2.2/module.php/oidc/.well-known/openid-federation');
//        $es = $this->federation->entityStatementFetcher()->fromNetwork('https://maiv1.incubator.geant.org/.well-known/openid-federation');
//        dd($es->getPayload(), $es->verifyWithKeySet());

//        $this->federationCache->cache->clear();
        //$this->protocolCache->set('value', 10, 'test');
        //dd($this->protocolCache, $this->protocolCache->get(null, 'test'));


//        $requestObjectFactory = (new Core())->requestObjectFactory();

        // {"alg":"none"}, {"iss":"joe",
        //      "exp":1300819380,
        //      "http://example.com/is_root":true}
//        $unprotectedJws = 'eyJhbGciOiJub25lIn0.' .
//        'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.';

//        $requestObject = $requestObjectFactory->fromToken($unprotectedJws);

//        dd($requestObject, $requestObject->getPayload(), $requestObject->getHeader());
//        $cache->clear();

        $trustChain = $this->federation
            ->trustChainResolver()
            ->for(
                'https://08-dap.localhost.markoivancic.from.hr/openid/entities/ALeaf/',
//                'https://trust-anchor.testbed.oidcfed.incubator.geant.org/oidc/rp/',
//                'https://relying-party-php.testbed.oidcfed.incubator.geant.org/',
//                'https://gorp.testbed.oidcfed.incubator.geant.org',
//                'https://maiv1.incubator.geant.org',
                [
//                    'https://trust-anchor.testbed.oidcfed.incubator.geant.org/',
                    'https://08-dap.localhost.markoivancic.from.hr/openid/entities/ABTrustAnchor/',
//                    'https://08-dap.localhost.markoivancic.from.hr/openid/entities/CTrustAnchor/',
                ],
            );

        $leaf = $trustChain->getResolvedLeaf();
//        dd($leaf);
        $leafFederationJwks = $leaf->getJwks();
//        dd($leafFederationJwks);
//        /** @psalm-suppress PossiblyNullArgument */
        $resolvedMetadata = $trustChain->getResolvedMetadata(EntityTypesEnum::OpenIdRelyingParty);
        $clientEntity = $this->clientEntityFactory->fromRegistrationData(
            $resolvedMetadata,
            RegistrationTypeEnum::FederatedAutomatic,
        );
//        dd($resolvedMetadata, $clientEntity);
        $jwksUri = $resolvedMetadata['jwks_uri'] ?? null;
        $signedJwksUri = $resolvedMetadata['signed_jwks_uri'] ?? null;
//        dd($leaf, $leafFederationJwks, $resolvedMetadata, $jwksUri, $signedJwksUri);
//        $cachedJwks = $jwksUri ? $this->jwks->jwksFetcher()->fromCache($jwksUri) : null;
//        $jwks = $jwksUri ? $this->jwks->jwksFetcher()->fromJwksUri($jwksUri) : null;

//$leafFederationJwks = [
//    'keys' =>
//        [
//            0 =>
//                [
//                    'alg' => 'RS256',
//                    'use' => 'sig',
//                    'kty' => 'RSA',
//                    'n' => 'pJgG9F_lwc2cFEC1l6q0fjJYxKPbtVGqJpDggDpDR8MgfbH0jUZP_RvhJGpl_09Bp-PfibLiwxchHZlrCx-fHQyGMaBRivUfq_p12ECEXMaFUcasCP6cyNrDfa5Uchumau4WeC21nYI1NMawiMiWFcHpLCQ7Ul8NMaCM_dkeruhm_xG0ZCqfwu30jOyCsnZdE0izJwPTfBRLpLyivu8eHpwjoIzmwqo8H-ZsbqR0vdRu20-MNS78ppTxwK3QmJhU6VO2r730F6WH9xJd_XUDuVeM4_6Z6WVDXw3kQF-jlpfcssPP303nbqVmfFZSUgS8buToErpMqevMIKREShsjMQ',
//                    'e' => 'AQAB',
//                    'kid' => 'F4VFObNusj3PHmrHxpqh4GNiuFHlfh-2s6xMJ95fLYA',
//                ],
//        ],
//];
//        $signedJwksUri = 'https://08-dap.localhost.markoivancic.from.hr/openid/entities/ALeaf/signed-jwks';
        $signedJwks = $signedJwksUri ? $this->jwks->jwksFetcher()
            ->fromSignedJwksUri($signedJwksUri, $leafFederationJwks) : null;
        $cachedSignedJwks = $signedJwksUri ? $this->jwks->jwksFetcher()->fromCache($signedJwksUri) : null;
        dd($signedJwksUri, $cachedSignedJwks, $signedJwks);
//        dd(
//            $signedJwksUri,
//            $cachedSignedJwks,
//            $signedJwks,
//        );

        return new JsonResponse(
            $trustChain->getResolvedMetadata(EntityTypesEnum::OpenIdRelyingParty),
        );
    }
}
