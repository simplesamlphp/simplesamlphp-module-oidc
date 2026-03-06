<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Exceptions\AuthorizationException;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\ValueAbstracts\ResolvedClientAuthenticationMethod;
use SimpleSAML\OpenID\Codebooks\ClientAssertionTypesEnum;
use SimpleSAML\OpenID\Codebooks\ClientAuthenticationMethodsEnum;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;
use Symfony\Component\HttpFoundation\Request;

class AuthenticatedOAuth2ClientResolver
{
    protected const KEY_CLIENT_ASSERTION_JTI = 'client_assertion_jti';

    public function __construct(
        protected readonly ClientRepository $clientRepository,
        protected readonly RequestParamsResolver $requestParamsResolver,
        protected readonly LoggerService $loggerService,
        protected readonly PsrHttpBridge $psrHttpBridge,
        protected readonly JwksResolver $jwksResolver,
        protected readonly ModuleConfig $moduleConfig,
        protected readonly Helpers $helpers,
        protected readonly ?ProtocolCache $protocolCache,
    ) {
    }

    public function forAnySupportedMethod(
        Request|ServerRequestInterface $request,
        ?ClientEntityInterface $preFetchedClient = null,
    ): ?ResolvedClientAuthenticationMethod {
        try {
            return
            $this->forPrivateKeyJwt($request, $preFetchedClient) ??
            $this->forClientSecretBasic($request, $preFetchedClient) ??
            $this->forClientSecretPost($request, $preFetchedClient) ??
            $this->forPublicClient($request, $preFetchedClient);
        } catch (\Throwable $exception) {
            $this->loggerService->error(
                'Error while trying to resolve authenticated client: ' .
                    $exception->getMessage(),
            );
            return null;
        }
    }

    /**
     * @throws AuthorizationException
     */
    public function forPublicClient(
        ServerRequestInterface|Request $request,
        ?ClientEntityInterface $preFetchedClient,
    ): ?ResolvedClientAuthenticationMethod {
        $this->loggerService->debug('Trying to resolve public client for request client ID.');

        if ($request instanceof Request) {
            $request = $this->psrHttpBridge->getPsrHttpFactory()->createRequest($request);
        }

        $clientId = $this->requestParamsResolver->getFromRequestBasedOnAllowedMethods(
            ParamsEnum::ClientId->value,
            $request,
            [HttpMethodsEnum::GET, HttpMethodsEnum::POST],
        );

        if (!is_string($clientId) || $clientId === '') {
            $this->loggerService->debug(
                'No client ID available in HTTP request, skipping for public client.',
            );
            return null;
        }

        $this->loggerService->debug('Client ID from HTTP request: ' . $clientId);

        $client = $this->resolveClientOrFail($clientId, $preFetchedClient);

        if ($client->isConfidential()) {
            $this->loggerService->debug(
                'Client with ID ' . $clientId . ' is confidential, aborting for public client.',
            );
            throw new AuthorizationException('Client is confidential.');
        }

        return new ResolvedClientAuthenticationMethod(
            $client,
            ClientAuthenticationMethodsEnum::None,
        );
    }

    /**
     * @throws AuthorizationException
     */
    public function forClientSecretBasic(
        Request|ServerRequestInterface $request,
        ?ClientEntityInterface $preFetchedClient = null,
    ): ?ResolvedClientAuthenticationMethod {
        $this->loggerService->debug('Trying to resolve authenticated client from basic auth.');

        if ($request instanceof Request) {
            $request = $this->psrHttpBridge->getPsrHttpFactory()->createRequest($request);
        }

        $authorizationHeader = $request->getHeader('Authorization')[0] ?? null;

        if (!is_string($authorizationHeader)) {
            $this->loggerService->debug(
                'No authorization header available for basic auth, skipping.',
            );
            return null;
        }

        if (!str_starts_with($authorizationHeader, 'Basic ')) {
            $this->loggerService->debug(
                'Authorization header is not in basic auth format, skipping.',
            );
            return null;
        }

        $decodedAuthorizationHeader = base64_decode(substr($authorizationHeader, 6), true);

        if ($decodedAuthorizationHeader === false) {
            $this->loggerService->debug(
                'Authorization header Basic value is invalid, skipping.',
            );
            return null;
        }

        if (!str_contains($decodedAuthorizationHeader, ':')) {
            $this->loggerService->debug(
                'Authorization header Basic value is invalid, skipping.',
            );
            return null;
        }

        $parts = explode(':', $decodedAuthorizationHeader, 2);
        $clientId = $parts[0];
        $clientSecret = $parts[1] ?? '';

        if ($clientId === '') {
            $this->loggerService->debug(
                'No client ID available in basic auth header, skipping.',
            );
            return null;
        }

        $this->loggerService->debug('Client ID from basic auth: ' . $clientId);

        $client = $this->resolveClientOrFail($clientId, $preFetchedClient);

        // Only do secret validation for confidential clients. Public clients
        // should not have a secret provided.
        if (!$client->isConfidential()) {
            $this->loggerService->debug(
                'Client with ID ' . $clientId . ' is not confidential, aborting basic auth validation.',
            );
            throw new AuthorizationException('Client is not confidential.');
        }

        if ($clientSecret === '') {
            $this->loggerService->error('No client secret available in basic auth header.');
            throw new AuthorizationException('No client secret available in basic auth header.');
        }

        $this->loggerService->debug('Client secret provided for basic auth, validating credentials.');

        $this->validateClientSecret($client, $clientSecret);

        $this->loggerService->debug('Client credentials from basic auth validated.');

        return new ResolvedClientAuthenticationMethod(
            $client,
            ClientAuthenticationMethodsEnum::ClientSecretBasic,
        );
    }

    /**
     * For client_secret_post authentication method.
     *
     * @throws AuthorizationException
     */
    public function forClientSecretPost(
        Request|ServerRequestInterface $request,
        ?ClientEntityInterface $preFetchedClient = null,
    ): ?ResolvedClientAuthenticationMethod {
        $this->loggerService->debug('Trying to resolve authenticated client from HTTP POST body.');

        if ($request instanceof Request) {
            $request = $this->psrHttpBridge->getPsrHttpFactory()->createRequest($request);
        }

        $clientId = $this->requestParamsResolver->getFromRequestBasedOnAllowedMethods(
            ParamsEnum::ClientId->value,
            $request,
            [HttpMethodsEnum::POST],
        );
        $clientSecret = $this->requestParamsResolver->getFromRequestBasedOnAllowedMethods(
            ParamsEnum::ClientSecret->value,
            $request,
            [HttpMethodsEnum::POST],
        );

        if (!is_string($clientId) || $clientId === '') {
            $this->loggerService->debug(
                'No client ID available in HTTP POST body, skipping client_secret_post.',
            );
            return null;
        }

        if (!is_string($clientSecret) || $clientSecret === '') {
            $this->loggerService->debug(
                'No client secret available in HTTP POST body, skipping client_secret_post.',
            );
            return null;
        }

        $this->loggerService->debug('Client ID from HTTP POST body: ' . $clientId);

        $client = $this->resolveClientOrFail($clientId, $preFetchedClient);

        // Only do secret validation for confidential clients. Public clients
        // should not have a secret provided.
        if (!$client->isConfidential()) {
            $this->loggerService->debug(
                'Client with ID ' . $clientId . ' is not confidential, aborting client_secret_post.',
            );
            throw new AuthorizationException('Client is not confidential.');
        }

        $this->loggerService->debug('Client secret provided for HTTP POST body, validating credentials.');

        $this->validateClientSecret($client, $clientSecret);

        $this->loggerService->debug('Client credentials from HTTP POST body validated.');

        return new ResolvedClientAuthenticationMethod(
            $client,
            ClientAuthenticationMethodsEnum::ClientSecretPost,
        );
    }

    /**
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     * @throws \SimpleSAML\OpenID\Exceptions\ClientAssertionException
     * @throws \SimpleSAML\Module\oidc\Exceptions\AuthorizationException
     * @throws \Psr\SimpleCache\InvalidArgumentException
     */
    public function forPrivateKeyJwt(
        Request|ServerRequestInterface $request,
        ?ClientEntityInterface $preFetchedClient = null,
    ): ?ResolvedClientAuthenticationMethod {
        $this->loggerService->debug('Trying to resolve authenticated client from private key JWT.');

        if ($request instanceof Request) {
            $request = $this->psrHttpBridge->getPsrHttpFactory()->createRequest($request);
        }

        $allowedServerRequestMethods = [HttpMethodsEnum::POST];

        $clientAssertionParam = $this->requestParamsResolver->getFromRequestBasedOnAllowedMethods(
            ParamsEnum::ClientAssertion->value,
            $request,
            $allowedServerRequestMethods,
        );

        if (!is_string($clientAssertionParam)) {
            $this->loggerService->debug('No client assertion available, skipping.');
            return null;
        }

        $this->loggerService->debug('Client assertion param received: ' . $clientAssertionParam);

        // private_key_jwt authentication method is used.
        // Check the expected assertion type param.
        $clientAssertionType = $this->requestParamsResolver->getFromRequestBasedOnAllowedMethods(
            ParamsEnum::ClientAssertionType->value,
            $request,
            $allowedServerRequestMethods,
        );

        if ($clientAssertionType !== ClientAssertionTypesEnum::JwtBaerer->value) {
            $this->loggerService->debug(
                'Client assertion type is not expected value, skipping.',
                ['expected' => ClientAssertionTypesEnum::JwtBaerer->value, 'actual' => $clientAssertionType],
            );
            return null;
        }

        $clientAssertion = $this->requestParamsResolver->parseClientAssertionToken($clientAssertionParam);

        $client = $this->resolveClientOrFail($clientAssertion->getIssuer(), $preFetchedClient);

        ($jwks = $this->jwksResolver->forClient($client)) || throw new AuthorizationException(
            'Can not validate Client Assertion, client JWKS not available.',
        );

        try {
            $clientAssertion->verifyWithKeySet($jwks);
        } catch (\Throwable $exception) {
            throw new AuthorizationException(
                'Client Assertion validation failed: ' . $exception->getMessage(),
            );
        }

        // Check if the Client Assertion token has already been used. Only
        // applicable if we have a cache available.
        if ($this->protocolCache) {
            ($this->protocolCache->has(self::KEY_CLIENT_ASSERTION_JTI, $clientAssertion->getJwtId()) === false)
            || throw new AuthorizationException('Client Assertion reused.');
        }

        ($client->getIdentifier() === $clientAssertion->getIssuer()) || throw new AuthorizationException(
            'Invalid Client Assertion Issuer claim.',
        );

        ($client->getIdentifier() === $clientAssertion->getSubject()) || throw new AuthorizationException(
            'Invalid Client Assertion Subject claim.',
        );

        // OpenID Core spec: The Audience SHOULD be the URL of the Authorization Server's Token Endpoint.
        // OpenID Federation spec: ...the audience of the signed JWT MUST be either the URL of the Authorization
        //     Server's Authorization Endpoint or the Authorization Server's Entity Identifier.
        $expectedAudience = [
            $this->moduleConfig->getModuleUrl(RoutesEnum::Token->value),
            $this->moduleConfig->getModuleUrl(RoutesEnum::Authorization->value),
            $this->moduleConfig->getIssuer(),
        ];

        (!empty(array_intersect($expectedAudience, $clientAssertion->getAudience()))) ||
        throw new AuthorizationException('Invalid Client Assertion Audience claim.');

        // Everything seems ok. Save it in a cache so we can check for reuse.
        $this->protocolCache?->set(
            $clientAssertion->getJwtId(),
            $this->helpers->dateTime()->getSecondsToExpirationTime($clientAssertion->getExpirationTime()),
            self::KEY_CLIENT_ASSERTION_JTI,
            $clientAssertion->getJwtId(),
        );

        return new ResolvedClientAuthenticationMethod(
            $client,
            ClientAuthenticationMethodsEnum::PrivateKeyJwt,
        );
    }

    public function findActiveClient(string $clientId): ?ClientEntityInterface
    {
        $client = $this->clientRepository->findById($clientId);

        if (is_null($client)) {
            $this->loggerService->debug('No client with ID ' . $clientId . ' found.');
            return null;
        }

        if (!$client->isEnabled()) {
            $this->loggerService->warning('Client with ID ' . $clientId . ' is disabled.');
            return null;
        }

        if ($client->isExpired()) {
            $this->loggerService->warning('Client with ID ' . $clientId . ' is expired.');
            return null;
        }

        $this->loggerService->debug('Client with ID ' . $clientId . ' is active, returning its instance.');
        return $client;
    }

    /**
     * @throws AuthorizationException
     */
    protected function resolveClientOrFail(
        string $clientId,
        ?ClientEntityInterface $preFetchedClient,
    ): ClientEntityInterface {
        $client = $preFetchedClient ?: $this->findActiveClientOrFail($clientId);

        if ($client->getIdentifier() !== $clientId) {
            $this->loggerService->error(
                'Client ID does not match, expected: ' . $clientId . ', actual: ' . $client->getIdentifier(),
            );
            throw new AuthorizationException('Client ID does not match.');
        }

        return $client;
    }

    /**
     * @throws AuthorizationException
     */
    public function findActiveClientOrFail(string $clientId): ClientEntityInterface
    {
        return $this->findActiveClient($clientId) ?? throw new AuthorizationException(
            'Client with ID ' . $clientId . ' is not active (either not found, not enabled, or expired).',
        );
    }

    /**
     * @throws AuthorizationException
     */
    public function validateClientSecret(ClientEntityInterface $client, string $clientSecret): void
    {
        hash_equals($client->getSecret(), $clientSecret) || throw new AuthorizationException(
            'Client secret is not valid.',
        );
    }
}
