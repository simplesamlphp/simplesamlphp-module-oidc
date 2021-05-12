<?php

namespace SimpleSAML\Modules\OpenIDConnect\Server;

use Defuse\Crypto\Key;
use League\OAuth2\Server\AuthorizationServer as OAuth2AuthorizationServer;
use League\OAuth2\Server\CodeChallengeVerifiers\CodeChallengeVerifierInterface;
use League\OAuth2\Server\CodeChallengeVerifiers\PlainVerifier;
use League\OAuth2\Server\CodeChallengeVerifiers\S256Verifier;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Grant\GrantTypeInterface;
use SimpleSAML\Modules\OpenIDConnect\Entity\Interfaces\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest as OAuth2AuthorizationRequest;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Modules\OpenIDConnect\Server\Exceptions\OidcServerException;
use SimpleSAML\Modules\OpenIDConnect\Server\Grants\Interfaces\PkceEnabledGrantTypeInterface;
use SimpleSAML\Modules\OpenIDConnect\Server\RequestTypes\AuthorizationRequest;

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
     * @var CodeChallengeVerifierInterface[]
     */
    protected $codeChallengeVerifiers = [];

    /**
     * @var bool $isPkceEnabled
     */
    protected $isPkceEnabled;

    /**
     * New server instance.
     *
     * @param ClientRepositoryInterface $clientRepository
     * @param AccessTokenRepositoryInterface $accessTokenRepository
     * @param ScopeRepositoryInterface $scopeRepository
     * @param CryptKey|string $privateKey
     * @param string|Key $encryptionKey
     * @param null|ResponseTypeInterface $responseType
     * @param bool $isPkceEnabled
     */
    public function __construct(
        ClientRepositoryInterface $clientRepository,
        AccessTokenRepositoryInterface $accessTokenRepository,
        ScopeRepositoryInterface $scopeRepository,
        $privateKey,
        $encryptionKey,
        ResponseTypeInterface $responseType = null,
        bool $isPkceEnabled = true
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

        if (\in_array('sha256', \hash_algos(), true)) {
            $s256Verifier = new S256Verifier();
            $this->codeChallengeVerifiers[$s256Verifier->getMethod()] = $s256Verifier;
        }

        $plainVerifier = new PlainVerifier();
        $this->codeChallengeVerifiers[$plainVerifier->getMethod()] = $plainVerifier;

        $this->isPkceEnabled = $isPkceEnabled;
    }

    /**
     * Validate an authorization request
     *
     * @param ServerRequestInterface $request
     *
     * @return OAuth2AuthorizationRequest
     * @throws OAuthServerException
     *
     */
    public function validateAuthorizationRequest(ServerRequestInterface $request): OAuth2AuthorizationRequest
    {
        /** @var string|null $state */
        $state = $request->getQueryParams()['state'] ?? null;

        $client = $this->getClientOrFail($request);
        $redirectUri = $this->getRedirectUriOrFail($client, $request);
        $scopes = $this->getScopesOrFail($client, $request, $redirectUri, $state);
        $grantType = $this->getGrantTypeOrFail($request, $redirectUri, $state);

        $oAuth2AuthorizationRequest = $grantType->validateAuthorizationRequest($request);

        $oAuth2AuthorizationRequest->setClient($client);
        $oAuth2AuthorizationRequest->setRedirectUri($redirectUri);
        $oAuth2AuthorizationRequest->setScopes($scopes);
        $oAuth2AuthorizationRequest->setGrantTypeId($grantType->getIdentifier());

        if ($state !== null) {
            $oAuth2AuthorizationRequest->setState($state);
        }

        if ($this->shouldCheckPkce($grantType, $client)) {
            $codeChallenge = $this->getCodeChallengeOrFail($request, $redirectUri);
            $codeChallengeMethod = $this->getCodeChallengeMethodOrFail($request, $redirectUri);

            $oAuth2AuthorizationRequest->setCodeChallenge($codeChallenge);
            $oAuth2AuthorizationRequest->setCodeChallengeMethod($codeChallengeMethod);
        }

        if (AuthorizationRequest::isOidcCandidate($oAuth2AuthorizationRequest)) {
            $authorizationRequest = AuthorizationRequest::fromOAuth2AuthorizationRequest($oAuth2AuthorizationRequest);

            /** @var string|null $nonce */
            $nonce = $request->getQueryParams()['nonce'] ?? null;
            if ($nonce !== null) {
                $authorizationRequest->setNonce($nonce);
            }

            return $authorizationRequest;
        }

        return $oAuth2AuthorizationRequest;
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
    protected function convertScopesQueryStringToArray(string $scopes): array
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

    protected function getGrantTypeOrFail(
        ServerRequestInterface $request,
        string $redirectUri,
        string $state = null
    ): GrantTypeInterface {
        foreach ($this->enabledGrantTypes as $grantType) {
            if ($grantType->canRespondToAuthorizationRequest($request)) {
                return $grantType;
            }
        }

        throw OidcServerException::unsupportedResponseType($redirectUri, $state);
    }

    protected function getCodeChallengeOrFail(
        ServerRequestInterface $request,
        string $redirectUri,
        string $state = null
    ): string {
        $codeChallenge = $request->getQueryParams()['code_challenge'] ?? null;

        if ($codeChallenge === null) {
            throw OidcServerException::invalidRequest(
                'code_challenge',
                'Code challenge must be provided for public clients',
                null,
                $redirectUri,
                $state
            );
        }

        // Validate code_challenge according to RFC-7636
        // @see: https://tools.ietf.org/html/rfc7636#section-4.2
        if (\preg_match('/^[A-Za-z0-9-._~]{43,128}$/', $codeChallenge) !== 1) {
            throw OidcServerException::invalidRequest(
                'code_challenge',
                'Code challenge must follow the specifications of RFC-7636.',
                null,
                $redirectUri
            );
        }

        return $codeChallenge;
    }

    protected function getCodeChallengeMethodOrFail(ServerRequestInterface $request, string $redirectUri): string
    {
        $codeChallengeMethod = $request->getQueryParams()['code_challenge_method'] ?? 'plain';

        if (\array_key_exists($codeChallengeMethod, $this->codeChallengeVerifiers) === false) {
            throw OidcServerException::invalidRequest(
                'code_challenge_method',
                'Code challenge method must be one of ' . \implode(', ', \array_map(
                    function ($method) {
                        return '`' . $method . '`';
                    },
                    \array_keys($this->codeChallengeVerifiers)
                )),
                null,
                $redirectUri
            );
        }

        return $codeChallengeMethod;
    }

    protected function shouldCheckPkce(GrantTypeInterface $grantType, ClientEntityInterface $client): bool
    {
        return $this->isPkceEnabled &&
            $grantType instanceof PkceEnabledGrantTypeInterface &&
            ! $client->isConfidential();
    }
}
