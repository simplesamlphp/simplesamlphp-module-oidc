<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;

class TokenIntrospectionController
{
    public function __construct(
        private readonly AccessTokenRepository $accessTokenRepository,
    )
    {
    }

    public function __invoke(Request $request): Response
    {
        if ($request->getMethod() !== 'POST') {
            return new JsonResponse([
                'error' => 'invalid_request',
                'error_description' => 'Token introspection endpoint only accepts POST requests'
            ], 405);
        }

        $authHeader = $request->headers->get('Authorization');
        if (empty($authHeader)) {
            return new JsonResponse([
                'error' => 'invalid_client',
                'error_description' => 'Client authentication is required'
            ], 401);
        }

        if (!preg_match('/^Bearer\s+(.+)$/i', $authHeader)) {
            return new JsonResponse([
                'error' => 'invalid_client',
                'error_description' => 'Invalid authorization header format'
            ], 401);
        }

        $contentType = $request->headers->get('Content-Type');
        if (empty($contentType) || !str_contains($contentType, 'application/x-www-form-urlencoded')) {
            return new JsonResponse([
                'error' => 'invalid_request',
                'error_description' => 'Content-Type must be application/x-www-form-urlencoded'
            ], 400);
        }

        $token = $request->request->get('token');
        if (empty($token)) {
            return new JsonResponse([
                'error' => 'invalid_request',
                'error_description' => 'Missing required parameter: token'
            ], 400);
        }

        return $this->introspectToken($token);
    }

    private function introspectToken(string $token): JsonResponse
    {
        try {
            // JWT format: header.payload.signature
            $tokenParts = explode('.', $token);

            if (count($tokenParts) !== 3) {
                return new JsonResponse(['active' => false], 200);
            }

            $payload = json_decode(base64_decode(strtr($tokenParts[1], '-_', '+/')), true);

            if (!is_array($payload) || !isset($payload['jti'])) {
                return new JsonResponse(['active' => false], 200);
            }

            $tokenId = $payload['jti'];

            $accessToken = $this->accessTokenRepository->findById($tokenId);

            if (!$accessToken instanceof AccessTokenEntity) {
                return new JsonResponse(['active' => false], 200);
            }

            if ($accessToken->isRevoked()) {
                return new JsonResponse(['active' => false], 200);
            }

            if ($accessToken->getExpiryDateTime() < new \DateTimeImmutable()) {
                return new JsonResponse(['active' => false], 200);
            }

            $introspectionResponse = [
                'active' => true,
                'scope' => implode(' ', array_map(fn($scope) => $scope->getIdentifier(), $accessToken->getScopes())),
                'client_id' => $accessToken->getClient()->getIdentifier(),
                'token_type' => 'Bearer',
                'exp' => $accessToken->getExpiryDateTime()->getTimestamp(),
            ];

            if (isset($payload['iat'])) {
                $introspectionResponse['iat'] = $payload['iat'];
            }

            return new JsonResponse($introspectionResponse, 200);

        } catch (\Exception $e) {
            return new JsonResponse(['active' => false], 200);
        }
    }
}
