<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Codebooks;

enum HttpMethodsEnum: string
{
    case GET = 'GET';
    case POST = 'POST';
}
