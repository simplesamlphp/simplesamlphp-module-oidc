<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\ResponseModes;

use League\OAuth2\Server\ResponseTypes\AbstractResponseType;

interface ResponseModeInterface
{
    public function buildResponse(string $redirectUri, array $params): AbstractResponseType;
}