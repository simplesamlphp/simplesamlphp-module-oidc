<?php

namespace SimpleSAML\Modules\OpenIDConnect\Server\Grants;

use League\OAuth2\Server\Grant\ImplicitGrant;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest as OAuth2AuthorizationRequest;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Error\BadRequest;
use SimpleSAML\Modules\OpenIDConnect\Server\Exceptions\OidcServerException;
use SimpleSAML\Modules\OpenIDConnect\Server\Grants\Traits\ClientRedirectUriValidationTrait;
use SimpleSAML\Modules\OpenIDConnect\Server\Grants\Traits\ScopesValidationTrait;

class OAuth2ImplicitGrant extends ImplicitGrant
{
    use ClientRedirectUriValidationTrait;
    use ScopesValidationTrait;

    /**
     * {@inheritdoc}
     */
    public function validateAuthorizationRequest(ServerRequestInterface $request): OAuth2AuthorizationRequest
    {
        /** @var string|null $state */
        $state = $request->getQueryParams()['state'] ?? null;

        try {
            $client = $this->getClientOrFail($request);
            $redirectUri = $this->getRedirectUriOrFail($client, $request);
        } catch (OidcServerException $exception) {
            $reason = \sprintf("%s %s", $exception->getMessage(), $exception->getHint() ?? '');
            throw new BadRequest($reason);
        }

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
