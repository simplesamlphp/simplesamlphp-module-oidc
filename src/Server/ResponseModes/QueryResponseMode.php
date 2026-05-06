<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\ResponseModes;

use League\OAuth2\Server\ResponseTypes\AbstractResponseType;
use Psr\Http\Message\ResponseInterface;
use League\OAuth2\Server\ResponseTypes\RedirectResponse;

class QueryResponseMode implements ResponseModeInterface
{
    public function buildResponse(string $redirectUri, array $params): AbstractResponseType
    {
        $response = new RedirectResponse();

        // TODO: copied from league/oauth2-server/src/Grant/AbstractAuthorizeGrant.php for now, but should be refactored to a common helper method
        $newRedirectUri = (\strstr($redirectUri, "?") === false) ? "?" : "&";
        $newRedirectUri .= \http_build_query($params);
        
        $response->setRedirectUri($newRedirectUri);

        return $response;
    }
}