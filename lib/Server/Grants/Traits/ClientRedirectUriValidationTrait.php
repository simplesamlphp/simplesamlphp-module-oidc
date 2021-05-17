<?php

namespace SimpleSAML\Modules\OpenIDConnect\Server\Grants\Traits;

use League\OAuth2\Server\RequestEvent;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Modules\OpenIDConnect\Entity\Interfaces\ClientEntityInterface;
use SimpleSAML\Modules\OpenIDConnect\Server\Exceptions\OidcServerException;

trait ClientRedirectUriValidationTrait
{
    /**
     * Get client entity.
     * @param ServerRequestInterface $request
     * @return ClientEntityInterface
     * @throws OidcServerException If client_id is missing or value is invalid.
     */
    protected function getClientOrFail(ServerRequestInterface $request): ClientEntityInterface
    {
        $clientId = $request->getQueryParams()['client_id'] ?? $request->getServerParams()['PHP_AUTH_USER'] ?? null;

        if ($clientId === null) {
            throw OidcServerException::invalidRequest('client_id');
        }

        $client = $this->clientRepository->getClientEntity($clientId);

        if ($client instanceof ClientEntityInterface === false) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::CLIENT_AUTHENTICATION_FAILED, $request));
            throw OidcServerException::invalidClient($request);
        }

        return $client;
    }


    /**
     * Get redirect URI.
     * @param ClientEntityInterface $client
     * @param ServerRequestInterface $request
     * @return string
     * @throws OidcServerException
     */
    protected function getRedirectUriOrFail(ClientEntityInterface $client, ServerRequestInterface $request): string
    {
        $redirectUri = $request->getQueryParams()['redirect_uri'] ?? null;

        // On OAuth2 redirect_uri is optional if there is only one registered, however we will always require it
        // since this is OIDC oriented package and in OIDC this parameter is required.
        if ($redirectUri === null) {
            throw OidcServerException::invalidRequest('redirect_uri');
        }

        /** @psalm-suppress PossiblyInvalidArgument */
        if (
            \is_string($client->getRedirectUri()) &&
            (\strcmp($client->getRedirectUri(), $redirectUri) !== 0)
        ) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::CLIENT_AUTHENTICATION_FAILED, $request));
            throw OidcServerException::invalidClient($request);
        } elseif (
            \is_array($client->getRedirectUri()) &&
            \in_array($redirectUri, $client->getRedirectUri(), true) === false
        ) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::CLIENT_AUTHENTICATION_FAILED, $request));
            throw OidcServerException::invalidClient($request);
        }

        return $redirectUri;
    }
}
