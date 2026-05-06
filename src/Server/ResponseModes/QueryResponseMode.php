<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\ResponseModes;

use League\OAuth2\Server\ResponseTypes\AbstractResponseType;
use League\OAuth2\Server\ResponseTypes\RedirectResponse;

class QueryResponseMode implements ResponseModeInterface
{
    public function buildResponse(string $redirectUri, array $params): AbstractResponseType
    {
        $separator = str_contains($redirectUri, '?') ? '&' : '?';
        $response = new RedirectResponse();
        $response->setRedirectUri($redirectUri . $separator . http_build_query($params));

        return $response;
    }
}