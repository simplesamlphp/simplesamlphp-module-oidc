<?php

namespace SimpleSAML\Module\oidc\Server\Grants\Interfaces;

use League\OAuth2\Server\RequestTypes\AuthorizationRequest as OAuth2AuthorizationRequest;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;

interface AuthorizationValidatableWithCheckerResultBagInterface
{
    /**
     * Validate authorization request using an existing ResultBag instance (with already validated checkers).
     * This is to evade usage of original validateAuthorizationRequest() method in which it is expected to
     * validate client and redirect_uri (which was already validated).
     *
     * @param ServerRequestInterface $request
     * @param ResultBagInterface $resultBag
     * @return OAuth2AuthorizationRequest
     */
    public function validateAuthorizationRequestWithCheckerResultBag(
        ServerRequestInterface $request,
        ResultBagInterface $resultBag
    ): OAuth2AuthorizationRequest;
}
