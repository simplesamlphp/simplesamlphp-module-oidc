<?php

namespace SimpleSAML\Modules\OpenIDConnect\Server\Grants;

use League\OAuth2\Server\Grant\ImplicitGrant;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest as OAuth2AuthorizationRequest;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Error\BadRequest;
use SimpleSAML\Modules\OpenIDConnect\Entity\Interfaces\ClientEntityInterface;
use SimpleSAML\Modules\OpenIDConnect\Server\Exceptions\OidcServerException;
use SimpleSAML\Modules\OpenIDConnect\Server\Grants\Interfaces\AuthorizationValidatableWithClientAndRedirectUriInterface;
use SimpleSAML\Modules\OpenIDConnect\Server\Grants\Traits\ClientRedirectUriValidationTrait;
use SimpleSAML\Modules\OpenIDConnect\Server\Grants\Traits\ScopesValidationTrait;

class OAuth2ImplicitGrant extends ImplicitGrant implements AuthorizationValidatableWithClientAndRedirectUriInterface
{
    use ScopesValidationTrait;

    public function validateAuthorizationRequestWithClientAndRedirectUri(
        ServerRequestInterface $request,
        ClientEntityInterface $client,
        string $redirectUri,
        string $state = null
    ): OAuth2AuthorizationRequest {
        // TODO mivanci refactor to rules
        $scopes = $this->getScopesOrFail($request, $this->scopeRepository, $this->defaultScope, $redirectUri, $state);

        $oAuth2AuthorizationRequest = new OAuth2AuthorizationRequest();

        $oAuth2AuthorizationRequest->setClient($client);
        $oAuth2AuthorizationRequest->setRedirectUri($redirectUri);
        $oAuth2AuthorizationRequest->setScopes($scopes);
        $oAuth2AuthorizationRequest->setGrantTypeId($this->getIdentifier());

        if ($state !== null) {
            $oAuth2AuthorizationRequest->setState($state);
        }

        return $oAuth2AuthorizationRequest;
    }
}
