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
        //protected OIDT $oidt,
    )
    {
    }

    public function __invoke(): Response
    {

        dd((new Federation(
            logger: new LoggerService(),
        ))
            ->entityStatementFetcher()
            ->forWellKnown('https://82-dap.localhost.markoivancic.from.hr/simplesamlphp/simplesamlphp-2.2/module.php/oidc/'));

        return new Response();
    }
}