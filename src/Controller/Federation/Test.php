<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controller\Federation;

use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Codebooks\EntityTypeEnum;
use SimpleSAML\OpenID\Federation;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Symfony\Component\Cache\Psr16Cache;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;

// TODO mivanci remove controller

/**
 * @psalm-suppress UnevaluatedCode
 */
class Test
{
    public function __construct(protected ModuleConfig $moduleConfig)
    {
    }

    public function __invoke(): Response
    {
        $cache = new Psr16Cache(new FilesystemAdapter(
            'oidc-federation',
            60,
            $this->moduleConfig->sspConfig()->getPathValue('cachedir'),
        ));

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
