<?php

declare(strict_types=1);

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * Copyright (C) 2018 by the Spanish Research and Academic Network.
 *
 * This code was developed by Universidad de Córdoba (UCO https://www.uco.es)
 * for the RedIRIS SIR service (SIR: http://www.rediris.es/sir)
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Module\oidc\Controller;

use Laminas\Diactoros\Response\JsonResponse;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\ResourceServer;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Error;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Controller\Traits\RequestTrait;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Services\ErrorResponder;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class UserInfoController
{
    use RequestTrait;

    public function __construct(
        private readonly ResourceServer $resourceServer,
        private readonly AccessTokenRepository $accessTokenRepository,
        private readonly UserRepository $userRepository,
        private readonly AllowedOriginRepository $allowedOriginRepository,
        private readonly ClaimTranslatorExtractor $claimTranslatorExtractor,
        private readonly PsrHttpBridge $psrHttpBridge,
        private readonly ErrorResponder $errorResponder,
    ) {
    }

    /**
     * @throws \SimpleSAML\Error\UserNotFound
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    public function __invoke(ServerRequestInterface $request): ResponseInterface
    {
        // Check if this is actually a CORS preflight request...
        if (strtoupper($request->getMethod()) === 'OPTIONS') {
            return $this->handleCors($request);
        }

        $authorization = $this->resourceServer->validateAuthenticatedRequest($request);

        /** @var string $tokenId */
        $tokenId = $authorization->getAttribute('oauth_access_token_id');
        /** @var string[] $scopes */
        $scopes = $authorization->getAttribute('oauth_scopes');

        $accessToken = $this->accessTokenRepository->findById($tokenId);
        if (!$accessToken instanceof AccessTokenEntity) {
            throw new Error\UserNotFound('Access token not found');
        }
        $user = $this->getUser($accessToken);

        $claims = $this->claimTranslatorExtractor->extract($scopes, $user->getClaims());
        $requestedClaims =  $accessToken->getRequestedClaims();
        $additionalClaims = $this->claimTranslatorExtractor->extractAdditionalUserInfoClaims(
            $requestedClaims,
            $user->getClaims(),
        );
        $claims = array_merge($additionalClaims, $claims);

        return new JsonResponse($claims);
    }

    public function userInfo(Request $request): Response
    {
        try {
            /**
             * @psalm-suppress DeprecatedMethod Until we drop support for old public/*.php routes, we need to bridge
             * between PSR and Symfony HTTP messages.
             */
            return $this->psrHttpBridge->getHttpFoundationFactory()->createResponse(
                $this->__invoke($this->psrHttpBridge->getPsrHttpFactory()->createRequest($request)),
            );
        } catch (OAuthServerException $exception) {
            return $this->errorResponder->forException($exception);
        }
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \SimpleSAML\Error\UserNotFound
     */
    private function getUser(AccessTokenEntity $accessToken): UserEntity
    {
        $userIdentifier = (string) $accessToken->getUserIdentifier();
        $user = $this->userRepository->getUserEntityByIdentifier($userIdentifier);
        if (!$user instanceof UserEntity) {
            throw new Error\UserNotFound("User $userIdentifier not found");
        }

        return $user;
    }
}
