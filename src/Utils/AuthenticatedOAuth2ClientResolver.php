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
use Throwable;

class AuthenticatedOAuth2ClientResolver
{
    protected const string KEY_CLIENT_ASSERTION_JTI = 'client_assertion_jti';


    public function __construct(
        protected readonly ClientRepository $clientRepository,
        protected readonly RequestParamsResolver $requestParamsResolver,
        protected readonly LoggerService $loggerService,
        protected readonly PsrHttpBridge $psrHttpBridge,
        protected readonly JwksResolver $jwksResolver,
        protected readonly ModuleConfig $moduleConfig,
        protected readonly Helpers $helpers,
        protected readonly ?ProtocolCache $protocolCache,
        protected readonly Routes $routes,
    ) {
    }


    /**
     * The client the request authenticates as, or null when it authenticates as none: either no supported
     * method was presented, or one was and the client was refused (unknown, not active, wrong secret, an
     * assertion which does not verify, credentials which do not fit the registration). A refusal is an
     * AuthorizationException from one of the methods and is logged here with its reason; the caller answers
     * `invalid_client` (RFC 6749 section 5.2, RFC 7521 section 4.2.1), which both cases deserve.
     *
     * Anything else thrown is not a verdict on the client and propagates: a database or cache failure while
     * looking the client up or checking assertion reuse is the OP's own fault, and answering it as
     * `invalid_client` would tell a client with valid credentials that they are wrong, and hide an outage
     * behind a 401. The endpoint answers such a failure as `server_error` instead.
     *
     * @throws \Throwable
     */
    public function forAnySupportedMethod(
        Request|ServerRequestInterface $request,
        ?ClientEntityInterface $preFetchedClient = null,
    ): ?ResolvedClientAuthenticationMethod {
        try {
            $resolved =
            $this->forPrivateKeyJwt($request, $preFetchedClient) ??
            $this->forClientSecretBasic($request, $preFetchedClient) ??
            $this->forClientSecretPost($request, $preFetchedClient) ??
            $this->forPublicClient($request, $preFetchedClient);

            if ($resolved !== null) {
                $this->refuseCredentialsWhichWentUnused($request, $resolved);
                $this->enforceRegisteredTokenEndpointAuthMethod($resolved);
            }

            return $resolved;
        } catch (AuthorizationException $exception) {
            $this->loggerService->warning(
                'Client authentication refused: ' . $exception->getMessage(),
            );
            return null;
        }
    }


    /**
     * Whether the request carries client credentials for any of the supported authentication methods: a client
     * assertion (private_key_jwt), a Basic Authorization header (client_secret_basic) or a client secret in the
     * POST body (client_secret_post). A bare client_id identifies the client without authenticating it, so it
     * does not count. What counts is an attempt, not a usable one: an empty assertion, which forPrivateKeyJwt()
     * goes on to refuse, a malformed Basic header, which forClientSecretBasic() skips, and a client_assertion_type
     * without an assertion, which nothing reads, are all presented credentials here. The exception is an empty
     * client secret, which forClientSecretPost() treats as absent, and so does this.
     *
     * For a caller which requires authentication, forAnySupportedMethod() answering null is refusal enough. A
     * caller for whom authentication is optional needs to tell a client that chose not to authenticate apart
     * from one that tried and failed, which that null does not; this does. forAnySupportedMethod() itself
     * uses it to keep a failed attempt from falling through to the public client (see
     * refuseCredentialsWhichWentUnused()).
     */
    public function presentsClientCredentials(Request|ServerRequestInterface $request): bool
    {
        if ($request instanceof Request) {
            $request = $this->psrHttpBridge->getPsrHttpFactory()->createRequest($request);
        }

        foreach ([ParamsEnum::ClientAssertion->value, ParamsEnum::ClientAssertionType->value] as $assertionParam) {
            if (
                is_string($this->requestParamsResolver->getFromRequestBasedOnAllowedMethods(
                    $assertionParam,
                    $request,
                    [HttpMethodsEnum::POST],
                ))
            ) {
                return true;
            }
        }

        if ($this->basicAuthorizationCredentials($request) !== null) {
            return true;
        }

        $clientSecret = $this->requestParamsResolver->getFromRequestBasedOnAllowedMethods(
            ParamsEnum::ClientSecret->value,
            $request,
            [HttpMethodsEnum::POST],
        );

        return is_string($clientSecret) && $clientSecret !== '';
    }


    /**
     * What follows the scheme in a Basic Authorization header, or null when the request carries no such header.
     * The scheme name is case-insensitive (RFC 9110, section 11.1), so `basic` and `BASIC` are the scheme as
     * much as `Basic` is; what follows it is handed back untouched for the caller to decode and judge. A bare
     * scheme is an empty credential rather than no header: PSR-7 implementations trim the field value, so
     * `Basic ` reaches this method as `Basic`, and a wallet which sent that did attempt to authenticate.
     */
    protected function basicAuthorizationCredentials(ServerRequestInterface $request): ?string
    {
        $authorizationHeader = $request->getHeader('Authorization')[0] ?? null;

        if (
            !is_string($authorizationHeader) ||
            preg_match('/^Basic(?:[ \t]+(.*))?$/i', $authorizationHeader, $matches) !== 1
        ) {
            return null;
        }

        return $matches[1] ?? '';
    }


    /**
     * A request which presented credentials and still resolved as a public client tried to authenticate and
     * failed: every credential method declined what it was given (a malformed Basic header, an assertion of
     * an unsupported type, an empty assertion), and only the bare client_id was left for forPublicClient()
     * to accept. That is a failed authentication - invalid_client under RFC 7521 section 4.2.1 for an
     * assertion and RFC 6749 section 5.2 otherwise - not an unauthenticated public client, so it is refused
     * here rather than let through as `none`. Throwing makes forAnySupportedMethod() answer null, as for
     * any other refusal.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\AuthorizationException
     */
    protected function refuseCredentialsWhichWentUnused(
        Request|ServerRequestInterface $request,
        ResolvedClientAuthenticationMethod $resolved,
    ): void {
        if (
            $resolved->getClientAuthenticationMethod()->isNone() &&
            $this->presentsClientCredentials($request)
        ) {
            throw new AuthorizationException(
                'Client credentials were presented, but none of them could be used to authenticate the client.',
            );
        }
    }


    /**
     * If the client has explicitly registered a token_endpoint_auth_method, the method it actually authenticated
     * with must match it. Enforced only when explicitly registered, preserving behavior for manually-managed
     * clients that do not have it configured. Throwing here results in client authentication failing (the caller
     * treats a null resolution as invalid_client).
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\AuthorizationException
     */
    protected function enforceRegisteredTokenEndpointAuthMethod(
        ResolvedClientAuthenticationMethod $resolved,
    ): void {
        // getTokenEndpointAuthMethod() returns the raw registered value, or null when nothing is registered (it does
        // not synthesize the OIDC DCR spec default), so null means "not configured" and is not enforced.
        $registeredMethod = $resolved->getClient()->getTokenEndpointAuthMethod();

        if ($registeredMethod === null) {
            return;
        }

        $usedMethod = $resolved->getClientAuthenticationMethod()->value;
        if ($registeredMethod !== $usedMethod) {
            throw new AuthorizationException(sprintf(
                'Client authenticated with "%s" but is registered to use "%s" (token_endpoint_auth_method).',
                $usedMethod,
                $registeredMethod,
            ));
        }
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\AuthorizationException
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
     * @throws \SimpleSAML\Module\oidc\Exceptions\AuthorizationException
     */
    public function forClientSecretBasic(
        Request|ServerRequestInterface $request,
        ?ClientEntityInterface $preFetchedClient = null,
    ): ?ResolvedClientAuthenticationMethod {
        $this->loggerService->debug('Trying to resolve authenticated client from basic auth.');

        if ($request instanceof Request) {
            $request = $this->psrHttpBridge->getPsrHttpFactory()->createRequest($request);
        }

        $basicCredentials = $this->basicAuthorizationCredentials($request);

        if ($basicCredentials === null) {
            $this->loggerService->debug(
                'No Basic authorization header available for basic auth, skipping.',
            );
            return null;
        }

        $decodedAuthorizationHeader = base64_decode($basicCredentials, true);

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
     * @throws \SimpleSAML\Module\oidc\Exceptions\AuthorizationException
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
     * A refused assertion is an AuthorizationException whatever refused it: one which does not parse, is
     * missing a claim or has expired, one the client's JWKS cannot be obtained or used for, and one which
     * does not verify are all the client's doing (RFC 7521 section 4.2.1). The exceptions the parser and the
     * JWKS resolver throw are converted here so that forAnySupportedMethod() can tell such a refusal from a
     * failure of the OP's own. The client lookup and the reuse cache are left to throw as themselves: a
     * database or cache which cannot answer is a server fault, not a verdict.
     *
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

        // Its length only, never the assertion: it is a credential until it expires, and one that can be replayed
        // wherever its replay protection is off (no protocol cache configured), so a debug log must not hold it.
        $this->loggerService->debug(
            sprintf('Client assertion param received (%d bytes, not logged).', strlen($clientAssertionParam)),
        );

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

        // Parsing reads nothing but the assertion, so whatever it throws - the library's exceptions for a token
        // which does not parse, a claim missing, of the wrong type or expired - is the assertion's fault. The
        // expiration time is read here too, at the one moment the assertion is judged: its accessor checks the
        // clock again on every call, and an assertion which expires while its JWKS is fetched would otherwise
        // throw the library's exception further down, past this conversion, as if the OP had failed.
        try {
            $clientAssertion = $this->requestParamsResolver->parseClientAssertionToken($clientAssertionParam);
            $clientAssertionExpirationTime = $clientAssertion->getExpirationTime();
        } catch (Throwable $exception) {
            throw new AuthorizationException(
                'Client Assertion could not be parsed: ' . $exception->getMessage(),
                previous: $exception,
            );
        }

        $client = $this->resolveClientOrFail($clientAssertion->getIssuer(), $preFetchedClient);

        // The fetcher answers null for a URI it cannot reach and keeps its cache troubles to itself, so what it
        // throws is about the material it got: a Signed JWKS which does not parse or verify, key data the JWK
        // library will not build a key set from, a header it chokes on. Each is the client's registration at
        // fault, whichever exception it comes out as - a TypeError from the JOSE library included.
        try {
            $jwks = $this->jwksResolver->forClient($client);
        } catch (Throwable $exception) {
            throw new AuthorizationException(
                'Can not validate Client Assertion, client JWKS not usable: ' . $exception->getMessage(),
                previous: $exception,
            );
        }

        $jwks || throw new AuthorizationException(
            'Can not validate Client Assertion, client JWKS not available.',
        );

        try {
            $clientAssertion->verifyWithKeySet($jwks);
        } catch (Throwable $exception) {
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
        // RFC 9126 (PAR): ...the authorization server MUST accept its issuer identifier, token endpoint URL,
        //     or pushed authorization request endpoint URL as values that identify it as an intended audience.
        // RFC 7662 has the introspection endpoint authenticate clients as RFC 6749 does, and the endpoint is
        //     advertised for private_key_jwt (RFC 8414), so an assertion addressed to that endpoint's own URL,
        //     as RFC 7523 section 3 allows, is accepted there like one addressed to the token endpoint.
        $expectedAudience = [
            $this->routes->getModuleUrl(RoutesEnum::Token->value),
            $this->routes->getModuleUrl(RoutesEnum::Authorization->value),
            $this->routes->getModuleUrl(RoutesEnum::PushedAuthorizationRequest->value),
            $this->routes->getModuleUrl(RoutesEnum::ApiOAuth2TokenIntrospection->value),
            $this->moduleConfig->getIssuer(),
        ];

        (!empty(array_intersect($expectedAudience, $clientAssertion->getAudience()))) ||
        throw new AuthorizationException('Invalid Client Assertion Audience claim.');

        // Everything seems ok. Save it in a cache so we can check for reuse.
        $this->protocolCache?->set(
            $clientAssertion->getJwtId(),
            $this->helpers->dateTime()->getSecondsToExpirationTime($clientAssertionExpirationTime),
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
     * @throws \SimpleSAML\Module\oidc\Exceptions\AuthorizationException
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
     * @throws \SimpleSAML\Module\oidc\Exceptions\AuthorizationException
     */
    public function findActiveClientOrFail(string $clientId): ClientEntityInterface
    {
        return $this->findActiveClient($clientId) ?? throw new AuthorizationException(
            'Client with ID ' . $clientId . ' is not active (either not found, not enabled, or expired).',
        );
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\AuthorizationException
     */
    public function validateClientSecret(ClientEntityInterface $client, string $clientSecret): void
    {
        hash_equals($client->getSecret(), $clientSecret) || throw new AuthorizationException(
            'Client secret is not valid.',
        );
    }
}
