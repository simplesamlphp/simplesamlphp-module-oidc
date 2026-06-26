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
 * Client Configuration Endpoint (Section 4, read). Read requests are
 * authenticated with the Registration Access Token issued at registration.
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
     * Entry point wired in routes.php. Dispatches POST (create) and GET (read).
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
                default => $this->routes->newResponse(
                    '',
                    Response::HTTP_METHOD_NOT_ALLOWED,
                    ['Allow' => HttpMethodsEnum::GET->value . ', ' . HttpMethodsEnum::POST->value],
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

        // Issue a Registration Access Token (RAT); only its hash is persisted,
        // the plaintext is returned once.
        $registrationAccessToken = $this->helpers->random()->getIdentifier();
        $client->setRegistrationAccessTokenHash($this->hashToken($registrationAccessToken));

        $this->clientRepository->add($client);

        $response = $this->buildClientInformationResponse($client);
        $response[ClaimsEnum::RegistrationAccessToken->value] = $registrationAccessToken;

        return $this->jsonResponse($response, Response::HTTP_CREATED);
    }

    /**
     * Handle a Client Read Request (Section 4.2) at the Client Configuration
     * Endpoint.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    protected function read(Request $request): Response
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

        return $this->jsonResponse($this->buildClientInformationResponse($client), Response::HTTP_OK);
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
    protected function buildClientInformationResponse(ClientEntityInterface $client): array
    {
        $response = [
            ClaimsEnum::ClientId->value => $client->getIdentifier(),
            ClaimsEnum::ClientIdIssuedAt->value => $client->getCreatedAt()?->getTimestamp(),
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
