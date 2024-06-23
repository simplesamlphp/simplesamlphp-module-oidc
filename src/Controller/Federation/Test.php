<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controller\Federation;

use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Federation;
use Symfony\Component\HttpFoundation\Response;

// TODO mivanci remove controller
class Test
{
    public function __construct(
    )
    {
    }

    public function __invoke(): Response
    {

        dd(
            (new Federation(
            logger: new LoggerService(),
        ))
            ->trustChainFetcher()
                ->for(
                    'https://82-dap.localhost.markoivancic.from.hr/openid/entities/a-leaf/',
                    [
                        'https://82-dap.localhost.markoivancic.from.hr/openid/entities/ab-trust-anchor/',
                        'https://82-dap.localhost.markoivancic.from.hr/openid/entities/c-trust-anchor/'
                    ]
                )
        );

        return new Response();
    }
}