<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers;

use Laminas\Diactoros\ServerRequestFactory;
use League\OAuth2\Server\ResourceServer;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\RefreshTokenRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientAuthenticationRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientIdRule;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class TokenIntrospectionController
{
    private ?string $authenticatedClientId = null;

    public function __construct(
        private readonly AccessTokenRepository $accessTokenRepository,
        private readonly ResourceServer $resourceServer,
        private readonly PsrHttpBridge $psrHttpBridge,
        private readonly RequestRulesManager $requestRulesManager,
        private readonly RefreshTokenRepository $refreshTokenRepository,
        private readonly ModuleConfig $moduleConfig = new ModuleConfig(),
    ) {
    }

    public function __invoke(Request $request): Response
    {
        // Check the request method
        if ($request->getMethod() !== 'POST') {
            return new JsonResponse(
                [
                    'error' => 'invalid_request',
                    'error_description' => 'Token introspection endpoint only accepts POST requests.',
                ],
                405,
            );
        }

        // Check the content type
        $contentType = (string)$request->headers->get('Content-Type', '');
        if ($contentType === '' || !str_contains($contentType, 'application/x-www-form-urlencoded')) {
            return new JsonResponse(
                [
                    'error' => 'invalid_request',
                    'error_description' => 'Content-Type must be application/x-www-form-urlencoded.',
                ],
                400,
            );
        }

        // Check client authentication
        try {
            $psr = ServerRequestFactory::fromGlobals();
            $psrRequest = $psr->withParsedBody($request->request->all());

            $resultBag = $this->requestRulesManager->check(
                $psrRequest,
                [
                    ClientIdRule::class,
                    ClientAuthenticationRule::class,
                ],
                false,
                ['POST'],
            );

            // Get client id to later check if the token is from the authenticated client
            $client = $resultBag->getOrFail(ClientIdRule::class)->getValue();
            $this->authenticatedClientId = $client->getIdentifier();
        } catch (OidcServerException | \Throwable $e) {
            return new JsonResponse(
                [
                    'error' => 'invalid_client',
                    'error_description' => 'Client authentication failed.',
                ],
                401,
            );
        }

        // Check if token is provided
        $token = (string)$request->request->get('token', '');
        if ($token === '') {
            return new JsonResponse(
                [
                    'error' => 'invalid_request',
                    'error_description' => 'Missing required parameter token.',
                ],
                400,
            );
        }

        // Check the token
        return $this->introspectToken($token);
    }

    private function introspectToken(string $token): JsonResponse
    {
        try {
            $psrRequest = ServerRequestFactory::fromGlobals()
                ->withHeader('Authorization', 'Bearer ' . $token);

            $authorization = $this->resourceServer->validateAuthenticatedRequest($psrRequest);

            $tokenId = $authorization->getAttribute('oauth_access_token_id');
            $accessToken = $this->accessTokenRepository->findById($tokenId);

            if (!$accessToken instanceof AccessTokenEntity) {
                return new JsonResponse(['active' => false], 200);
            }

            if ($accessToken->getClient()->getIdentifier() !== $this->authenticatedClientId) {
                return new JsonResponse(['active' => false], 200);
            }

            if ($accessToken->isRevoked()) {
                return new JsonResponse(['active' => false], 200);
            }

            $tokenParts = explode('.', $token);
            $payload = json_decode(base64_decode(strtr($tokenParts[1], '-_', '+/')), true);

            $receivedTokenIssuer = $payload['iss'];
            $expectedTokenIssuer = $this->moduleConfig->getIssuer();
            if ($receivedTokenIssuer !== $expectedTokenIssuer) {
                return new JsonResponse(['active' => false,
                    'cause' => 'token issuer mismatch, expected: ' . $expectedTokenIssuer . ' actual: ' . $receivedTokenIssuer], 200);
            }

            $introspectionResponse = [
                'active' => true,
                'scope' => implode(' ', array_map(static fn($scope) => $scope->getIdentifier(), $accessToken->getScopes())),
                'client_id' => $accessToken->getClient()->getIdentifier(),
                'username' => (string) $accessToken->getUserIdentifier(),
                'token_type' => 'Bearer',
                'exp' => $accessToken->getExpiryDateTime()->getTimestamp(),
            ];

            $introspectionClaims = ['iat', 'nbf', 'sub', 'aud', 'iss', 'jti'];
            foreach ($introspectionClaims as $claim) {
                if (isset($payload[$claim])) {
                    $introspectionResponse[$claim] = $payload[$claim];
                }
            }
            return new JsonResponse($introspectionResponse, 200);
        } catch (\Throwable) {
            return new JsonResponse(['active' => false], 200);
        }
    }
}
