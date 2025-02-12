<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\Grants\Interfaces;

use League\OAuth2\Server\RequestTypes\AuthorizationRequest as OAuth2AuthorizationRequest;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;

interface AuthorizationValidatableWithRequestRules
{
    /**
     * Validate authorization request using an existing ResultBag instance (with already validated checkers).
     * This is to evade usage of original validateAuthorizationRequest() method in which it is expected to
     * validate client and redirect_uri (which was already validated).
     */
    public function validateAuthorizationRequestWithRequestRules(
        ServerRequestInterface $request,
        ResultBagInterface $resultBag,
    ): OAuth2AuthorizationRequest;
}
