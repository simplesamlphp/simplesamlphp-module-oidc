<?php

namespace SimpleSAML\Modules\OpenIDConnect\Utils\Checker;

use Laminas\Diactoros\ServerRequest;
use Psr\Http\Message\ServerRequestInterface;

interface RequestRule
{
    public function checkRule(ServerRequestInterface $request): array;
}
