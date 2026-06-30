<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers;

use League\OAuth2\Server\Exception\OAuthServerException;
use SimpleSAML\Module\oidc\Codebooks\DcrRegistrationAuthEnum;
use SimpleSAML\Module\oidc\Codebooks\RegistrationTypeEnum;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Factories\Entities\ClientEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\Registration\ClientMetadataValidator;
use SimpleSAML\Module\oidc\Services\ErrorResponder;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * OpenID Connect Dynamic Client Registration 1.0 endpoint.
 *
 * Implements the Client Registration Endpoint (Section 3, create) and the
 * Client Configuration Endpoint (RFC 7592). The Client Configuration Endpoint
 * supports read (GET), update (PUT) and delete (DELETE) of a dynamically
 * registered client; all three are authenticated with the Registration Access
 * Token issued at registration.
 */
class RegistrationController
{
    private const string HASH_ALGORITHM = 'sha256';

    public function __construct(
        private readonly ModuleConfig $moduleConfig,
        private readonly ClientMetadataValidator $clientMetadataValidator,
        private readonly ClientEntityFactory $clientEntityFactory,
        private readonly ClientRepository $clientRepository,
        private readonly ErrorResponder $errorResponder,
        private readonly Helpers $helpers,
        private readonly Routes $routes,
        private readonly LoggerService $logger,
    ) {
    }

    /**
     * Entry point wired in routes.php. Dispatches POST (create) at the
     * registration endpoint, and GET (read) / PUT (update) / DELETE (delete) at
     * the Client Configuration Endpoint.
     */
    public function registration(Request $request): Response
    {
        try {
            if (!$this->moduleConfig->getDcrEnabled()) {
                $this->logger->error('RegistrationController: registration endpoint is disabled.');
                return $this->routes->newResponse('', Response::HTTP_NOT_FOUND);
            }

            return match (strtoupper($request->getMethod())) {
                HttpMethodsEnum::POST->value => $this->register($request),
                HttpMethodsEnum::GET->value => $this->read($request),
                HttpMethodsEnum::PUT->value => $this->update($request),
                HttpMethodsEnum::DELETE->value => $this->delete($request),
                default => $this->routes->newResponse(
                    '',
                    Response::HTTP_METHOD_NOT_ALLOWED,
                    ['Allow' => implode(', ', [
                        HttpMethodsEnum::GET->value,
                        HttpMethodsEnum::POST->value,
                        HttpMethodsEnum::PUT->value,
                        HttpMethodsEnum::DELETE->value,
                    ])],
                ),
            };
        } catch (OAuthServerException $exception) {
            $this->logger->error(
                'RegistrationController: error processing registration request: ' . $exception->getMessage(),
            );
            return $this->errorResponder->forExceptionJson($exception);
        } catch (\Throwable $exception) {
            $this->logger->error(
                'RegistrationController: error processing registration request: ' . $exception->getMessage(),
            );

            return $this->errorResponder->forExceptionJson(
                OidcServerException::serverError('Unable to process the registration request.'),
            );
        }
    }

    /**
     * Handle a Client Registration Request (Section 3.1).
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    protected function register(Request $request): Response
    {
        $this->guardAccess($request);

        $metadata = $this->parseMetadata($request);
        $metadata = $this->clientMetadataValidator->validate($metadata);

        $client = $this->clientEntityFactory->fromRegistrationData($metadata, RegistrationTypeEnum::Dynamic);

        // Issue a Registration Access Token (RAT); only its hash is persisted, the plaintext is returned once.
        $registrationAccessToken = $this->issueRegistrationAccessToken($client);

        $this->clientRepository->add($client);

        return $this->jsonResponse(
            $this->buildClientInformationResponse($client, $registrationAccessToken),
            Response::HTTP_CREATED,
        );
    }

    /**
     * Handle a Client Read Request (Section 4.2) at the Client Configuration
     * Endpoint.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    protected function read(Request $request): Response
    {
        $client = $this->authenticateConfigurationRequest($request);

        // RFC 7592 Section 3 requires the Client Information Response to include a registration_access_token. Only
        // the hash is stored, so we cannot return the original plaintext; instead we rotate the token on read,
        // persist the new hash and return the new plaintext (RFC 7592 Section 2.1 permits the returned token to
        // differ from the one issued previously; the client must then use the new token).
        $registrationAccessToken = $this->issueRegistrationAccessToken($client);
        $this->clientRepository->update($client);

        return $this->jsonResponse(
            $this->buildClientInformationResponse($client, $registrationAccessToken),
            Response::HTTP_OK,
        );
    }

    /**
     * Handle a Client Update Request (RFC 7592, Section 2.2) at the Client
     * Configuration Endpoint. The request fully replaces the client's metadata.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    protected function update(Request $request): Response
    {
        $client = $this->authenticateConfigurationRequest($request);

        $metadata = $this->parseMetadata($request);

        // If the body carries client_id / client_secret, they MUST match the
        // current client (RFC 7592, Section 2.2). The client_secret is then
        // dropped so it cannot be used to override the stored value.
        /** @var mixed $bodyClientId */
        $bodyClientId = $metadata[ClaimsEnum::ClientId->value] ?? null;
        if ($bodyClientId !== null && $bodyClientId !== $client->getIdentifier()) {
            throw OidcServerException::invalidClientMetadata('The client_id must match the client being updated.');
        }
        /** @var mixed $bodyClientSecret */
        $bodyClientSecret = $metadata[ClaimsEnum::ClientSecret->value] ?? null;
        if ($bodyClientSecret !== null && $bodyClientSecret !== $client->getSecret()) {
            throw OidcServerException::invalidClientMetadata(
                'The client_secret must match the client being updated.',
            );
        }
        unset($metadata[ClaimsEnum::ClientSecret->value]);

        $metadata = $this->clientMetadataValidator->validate($metadata);

        $updatedClient = $this->clientEntityFactory->fromRegistrationData(
            $metadata,
            RegistrationTypeEnum::Dynamic,
            existingClient: $client,
        );

        // Rotate the Registration Access Token: RFC 7592 Section 3 requires it in the response, and only its hash is
        // stored. The factory carries over the previous hash from the existing client, which we overwrite here.
        $registrationAccessToken = $this->issueRegistrationAccessToken($updatedClient);
        $this->clientRepository->update($updatedClient);

        return $this->jsonResponse(
            $this->buildClientInformationResponse($updatedClient, $registrationAccessToken),
            Response::HTTP_OK,
        );
    }

    /**
     * Handle a Client Delete Request (RFC 7592, Section 2.3) at the Client
     * Configuration Endpoint.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    protected function delete(Request $request): Response
    {
        $client = $this->authenticateConfigurationRequest($request);

        $this->clientRepository->delete($client);

        return $this->routes->newResponse('', Response::HTTP_NO_CONTENT);
    }

    /**
     * Authenticate a Client Configuration Endpoint request (read / update /
     * delete) using the client_id query parameter and the Registration Access
     * Token, returning the resolved client.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    protected function authenticateConfigurationRequest(Request $request): ClientEntityInterface
    {
        /** @var mixed $clientId */
        $clientId = $request->query->all()[ClaimsEnum::ClientId->value] ?? null;
        $token = $this->helpers->http()->getBearerToken($request->headers->get('Authorization'));

        if (!is_string($clientId) || $clientId === '' || $token === null) {
            throw OidcServerException::accessDenied('A valid client_id and Registration Access Token are required.');
        }

        $client = $this->clientRepository->findById($clientId);
        $expectedHash = $client?->getRegistrationAccessTokenHash();

        // Per Section 4.4, never reveal whether a client exists: respond 401
        // for every failure case (not 404).
        if (
            $client === null ||
            $client->getRegistrationType() !== RegistrationTypeEnum::Dynamic ||
            $expectedHash === null ||
            !hash_equals($expectedHash, $this->hashToken($token))
        ) {
            throw OidcServerException::accessDenied('Invalid Registration Access Token.');
        }

        return $client;
    }

    /**
     * Enforce the configured access-control mode for the registration endpoint.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    protected function guardAccess(Request $request): void
    {
        if ($this->moduleConfig->getDcrRegistrationAuth() !== DcrRegistrationAuthEnum::InitialAccessToken) {
            return;
        }

        $token = $this->helpers->http()->getBearerToken($request->headers->get('Authorization'));
        $allowedTokens = $this->moduleConfig->getDcrInitialAccessTokens();

        if ($token === null) {
            throw OidcServerException::accessDenied('A valid Initial Access Token is required.');
        }

        foreach ($allowedTokens as $allowedToken) {
            if (hash_equals($allowedToken, $token)) {
                return;
            }
        }

        throw OidcServerException::accessDenied('The provided Initial Access Token is not valid.');
    }

    /**
     * Parse and JSON-decode the request body into a metadata array.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    protected function parseMetadata(Request $request): array
    {
        // RFC 7591 Section 3.1 / RFC 7592 Section 2.2: registration (create) and update requests carry a JSON
        // document and MUST use Content-Type: application/json. Reject other media types rather than parsing them.
        // Parameters such as "; charset=utf-8" are allowed; the comparison is on the media type only.
        $contentType = strtolower(trim(explode(';', (string)$request->headers->get('Content-Type', ''))[0]));
        if ($contentType !== 'application/json') {
            throw OidcServerException::invalidRequest(
                'Content-Type',
                'Registration requests must use Content-Type: application/json.',
            );
        }

        $body = $request->getContent();

        try {
            /** @var mixed $decoded */
            $decoded = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw OidcServerException::invalidClientMetadata('The request body must be a valid JSON object.');
        }

        if (!is_array($decoded) || array_is_list($decoded)) {
            throw OidcServerException::invalidClientMetadata('The request body must be a JSON object.');
        }

        return $decoded;
    }

    /**
     * Build the Client Information Response (Section 3.2 / 4.3) from the
     * persisted client.
     */
    protected function buildClientInformationResponse(
        ClientEntityInterface $client,
        string $registrationAccessToken,
    ): array {
        $response = [
            ClaimsEnum::ClientId->value => $client->getIdentifier(),
            ClaimsEnum::ClientIdIssuedAt->value => $client->getCreatedAt()?->getTimestamp(),
            // RFC 7592 Section 3: both registration_access_token and registration_client_uri are REQUIRED in the
            // Client Information Response (the response shape used by create, read and update).
            ClaimsEnum::RegistrationAccessToken->value => $registrationAccessToken,
            ClaimsEnum::RegistrationClientUri->value => $this->routes->getModuleUrl(
                RoutesEnum::Registration->value,
                [ClaimsEnum::ClientId->value => $client->getIdentifier()],
            ),
            ClaimsEnum::RedirectUris->value => $client->getRedirectUris(),
            ClaimsEnum::ClientName->value => $client->getName(),
            ClaimsEnum::Scope->value => implode(' ', $client->getScopes()),
        ];

        if ($client->isConfidential()) {
            $response[ClaimsEnum::ClientSecret->value] = $client->getSecret();
            // 0 indicates the client secret does not expire.
            $response[ClaimsEnum::ClientSecretExpiresAt->value] = 0;
        }

        if (($idTokenSignedResponseAlg = $client->getIdTokenSignedResponseAlg()) !== null) {
            $response[ClaimsEnum::IdTokenSignedResponseAlg->value] = $idTokenSignedResponseAlg;
        }

        if (($requestUris = $client->getRequestUris()) !== []) {
            $response[ClaimsEnum::RequestUris->value] = $requestUris;
        }

        $response[ClaimsEnum::GrantTypes->value] = $client->getGrantTypes();
        $response[ClaimsEnum::ResponseTypes->value] = $client->getResponseTypes();
        $response[ClaimsEnum::TokenEndpointAuthMethod->value] = $client->getTokenEndpointAuthMethod();

        if (($defaultMaxAge = $client->getDefaultMaxAge()) !== null) {
            $response[ClaimsEnum::DefaultMaxAge->value] = $defaultMaxAge;
        }
        if ($client->getRequireAuthTime()) {
            $response[ClaimsEnum::RequireAuthTime->value] = true;
        }
        if (($defaultAcrValues = $client->getDefaultAcrValues()) !== []) {
            $response[ClaimsEnum::DefaultAcrValues->value] = $defaultAcrValues;
        }

        // Echo back the stored informational ("store & echo") metadata.
        $extraMetadata = $client->getExtraMetadata();
        foreach (ClientEntityFactory::STORE_AND_ECHO_METADATA_KEYS as $key) {
            if (array_key_exists($key, $extraMetadata)) {
                /** @psalm-suppress MixedAssignment */
                $response[$key] = $extraMetadata[$key];
            }
        }

        return $response;
    }

    /**
     * Mint a fresh Registration Access Token, store only its hash on the client, and return the plaintext (returned
     * once in the Client Information Response). Used at registration and rotated on each read/update.
     */
    protected function issueRegistrationAccessToken(ClientEntityInterface $client): string
    {
        $registrationAccessToken = $this->helpers->random()->getIdentifier();
        $client->setRegistrationAccessTokenHash($this->hashToken($registrationAccessToken));

        return $registrationAccessToken;
    }

    protected function hashToken(string $token): string
    {
        return hash(self::HASH_ALGORITHM, $token);
    }

    protected function jsonResponse(array $body, int $status): Response
    {
        return $this->routes->newJsonResponse(
            $body,
            $status,
            ['Cache-Control' => 'no-store', 'Pragma' => 'no-cache'],
        );
    }
}
