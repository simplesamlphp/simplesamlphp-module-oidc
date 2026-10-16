<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\ResponseModes;

use League\OAuth2\Server\ResponseTypes\AbstractResponseType;
use SimpleSAML\OpenID\Codebooks\ResponseModesEnum;

interface ResponseModeInterface
{
    public function buildResponse(string $redirectUri, array $params): AbstractResponseType;


    /**
     * The `response_mode` value of this response mode, by which it can be kept where the response mode itself must
     * not go, and found again (ResponseModeResolver).
     */
    public function getMode(): ResponseModesEnum;
}
