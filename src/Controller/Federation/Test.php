<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controller\Federation;

use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Codebooks\EntityTypeEnum;
use SimpleSAML\OpenID\Core;
use SimpleSAML\OpenID\Federation;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;

// TODO mivanci remove controller

/**
 * @psalm-suppress UnevaluatedCode
 */
class Test
{
//    public function __construct(protected ModuleConfig $moduleConfig)
//    {
//    }

    public function __invoke(): Response
    {
//        $cache = new Psr16Cache(new FilesystemAdapter(
//            'oidc-federation',
//            60,
//            $this->moduleConfig->sspConfig()->getPathValue('cachedir'),
//        ));

        $requestObjectFactory = (new Core())->getRequestObjectFactory();

        // {"alg":"none"}, {"iss":"joe",
        //      "exp":1300819380,
        //      "http://example.com/is_root":true}
        $unprotectedJws = 'eyJhbGciOiJub25lIn0.' .
        'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.';

        $requestObject = $requestObjectFactory->fromToken($unprotectedJws);

        dd($requestObject, $requestObject->getPayload(), $requestObject->getHeader());
//        $cache->clear();

        $trustChain = (new Federation(
            maxCacheDuration: new \DateInterval('PT30S'),
            cache: $cache,
            logger: new LoggerService(),
        ))
            ->trustChainResolver()
            ->for(
                'https://08-dap.localhost.markoivancic.from.hr/openid/entities/ALeaf/',
                [
                    'https://08-dap.localhost.markoivancic.from.hr/openid/entities/ABTrustAnchor/',
                    'https://08-dap.localhost.markoivancic.from.hr/openid/entities/CTrustAnchor/',
                ],
            );

        return new JsonResponse(
            $trustChain->getResolvedMetadata(EntityTypeEnum::OpenIdRelyingParty),
        );
    }
}
