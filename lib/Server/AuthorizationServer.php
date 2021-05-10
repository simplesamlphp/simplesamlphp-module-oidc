<?php

namespace SimpleSAML\Modules\OpenIDConnect\Server;

use Defuse\Crypto\Key;
use League\OAuth2\Server\AuthorizationServer as OAuth2AuthorizationServer;
use League\OAuth2\Server\CryptKey;
use SimpleSAML\Modules\OpenIDConnect\Entity\Interfaces\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Modules\OpenIDConnect\Server\Exceptions\OidcServerException;

class AuthorizationServer extends OAuth2AuthorizationServer
{
    public const SCOPE_DELIMITER_STRING = ' ';

    /**
     * @var ClientRepositoryInterface
     */
    protected $clientRepository;

    /**
     * @var ScopeRepositoryInterface
     */
    protected $scopeRepository;

    /**
     * @var string
     */
    protected $defaultScope = '';

    /**
     * New server instance.
     *
     * @param ClientRepositoryInterface $clientRepository
     * @param AccessTokenRepositoryInterface $accessTokenRepository
     * @param ScopeRepositoryInterface $scopeRepository
     * @param CryptKey|string $privateKey
     * @param string|Key $encryptionKey
     * @param null|ResponseTypeInterface $responseType
     */
    public function __construct(
        ClientRepositoryInterface $clientRepository,
        AccessTokenRepositoryInterface $accessTokenRepository,
        ScopeRepositoryInterface $scopeRepository,
        $privateKey,
        $encryptionKey,
        ResponseTypeInterface $responseType = null
    ) {
        parent::__construct(
            $clientRepository,
            $accessTokenRepository,
            $scopeRepository,
            $privateKey,
            $encryptionKey,
            $responseType
        );

        $this->clientRepository = $clientRepository;
        $this->scopeRepository = $scopeRepository;
    }

    /**
     * Validate an authorization request
     *
     * @param ServerRequestInterface $request
     *
     * @return AuthorizationRequest
     * @throws OAuthServerException
     *
     */
    public function validateAuthorizationRequest(ServerRequestInterface $request): AuthorizationRequest
    {
        $state = $request->getQueryParams()['state'] ?? null;

        // TODO mivanci
        // Override validation in each grant
        // Handle authorization request instance here

        $client = $this->getClientOrFail($request);
        $redirectUri = $this->getRedirectUriOrFail($client, $request);
        $scopes = $this->getScopesOrFail($client, $request, $redirectUri, $state);

        foreach ($this->enabledGrantTypes as $grantType) {
            if ($grantType->canRespondToAuthorizationRequest($request)) {
                return $grantType->validateAuthorizationRequest($request);
            }
        }

        throw OidcServerException::unsupportedResponseType($redirectUri, $state);
    }

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
    private function getRedirectUriOrFail(ClientEntityInterface $client, ServerRequestInterface $request): string
    {
        $redirectUri = $request->getQueryParams()['redirect_uri'] ?? null;

        // Return default redirect URI if none provided on request.
        if ($redirectUri === null) {
            // In OAuth2, redirect_uri is optional if only one is registered.
            /** @psalm-suppress PossiblyInvalidArgument */
            if (
                empty($client->getRedirectUri()) ||
                (\is_array($client->getRedirectUri()) && \count($client->getRedirectUri()) !== 1)
            ) {
                $this->getEmitter()->emit(new RequestEvent(RequestEvent::CLIENT_AUTHENTICATION_FAILED, $request));
                throw OidcServerException::invalidClient($request);
            }

            /** @psalm-suppress InvalidReturnStatement */
            return \is_array($client->getRedirectUri())
                ? $client->getRedirectUri()[0]
                : $client->getRedirectUri();
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

    protected function getScopesOrFail(
        ClientEntityInterface $client,
        ServerRequestInterface $request,
        string $redirectUri = null,
        string $state = null
    ): array {
        $scopes = $this->convertScopesQueryStringToArray($request->getQueryParams()['scope'] ?? $this->defaultScope);

        $validScopes = [];

        foreach ($scopes as $scopeItem) {
            $scope = $this->scopeRepository->getScopeEntityByIdentifier($scopeItem);

            if ($scope instanceof ScopeEntityInterface === false) {
                throw OidcServerException::invalidScope($scopeItem, $redirectUri, $state);
            }

            // Since we register clients with specific scopes upfront, we can check for valid scopes for the client.
            if (! \in_array($scope->getIdentifier(), $client->getScopes(), true)) {
                throw OidcServerException::invalidScope($scopeItem, $redirectUri, $state);
            }

            $validScopes[] = $scope;
        }

        return $validScopes;
    }

    /**
     * Converts a scopes query string to an array to easily iterate for validation.
     *
     * @param string $scopes
     *
     * @return array
     */
    private function convertScopesQueryStringToArray(string $scopes): array
    {
        return \array_filter(\explode(self::SCOPE_DELIMITER_STRING, \trim($scopes)), function ($scope) {
            return !empty($scope);
        });
    }

    /**
     * @return string
     */
    public function getDefaultScope(): string
    {
        return $this->defaultScope;
    }

    /**
     * @param string $defaultScope
     */
    public function setDefaultScope($defaultScope): void
    {
        $this->defaultScope = $defaultScope;
    }
}
