<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\ResponseModes;

use League\OAuth2\Server\ResponseTypes\AbstractResponseType;
use League\OAuth2\Server\ResponseTypes\RedirectResponse;
use SimpleSAML\OpenID\Codebooks\ResponseModesEnum;

class FragmentResponseMode implements ResponseModeInterface
{
    public function buildResponse(string $redirectUri, array $params): AbstractResponseType
    {
        $separator = str_contains($redirectUri, '#') ? '&' : '#';
        $response = new RedirectResponse();
        $response->setRedirectUri($redirectUri . $separator . http_build_query($params));

        return $response;
    }


    public function getMode(): ResponseModesEnum
    {
        return ResponseModesEnum::Fragment;
    }
}
