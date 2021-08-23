<?php

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
use Laminas\Diactoros\ServerRequest;
use League\OAuth2\Server\ResourceServer;
use SimpleSAML\Error\UserNotFound;
use SimpleSAML\Module\oidc\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Entity\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entity\UserEntity;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Services\RequestedClaimsEncoderService;

class OpenIdConnectUserInfoController
{
    /**
     * @var ResourceServer
     */
    private $resourceServer;

    /**
     * @var AccessTokenRepository
     */
    private $accessTokenRepository;

    /**
     * @var UserRepository
     */
    private $userRepository;

    /**
     * @var ClaimTranslatorExtractor
     */
    private $claimTranslatorExtractor;

    public function __construct(
        ResourceServer $resourceServer,
        AccessTokenRepository $accessTokenRepository,
        UserRepository $userRepository,
        ClaimTranslatorExtractor $claimTranslatorExtractor
    ) {
        $this->resourceServer = $resourceServer;
        $this->accessTokenRepository = $accessTokenRepository;
        $this->userRepository = $userRepository;
        $this->claimTranslatorExtractor = $claimTranslatorExtractor;
    }

    public function __invoke(ServerRequest $request): JsonResponse
    {
        $authorization = $this->resourceServer->validateAuthenticatedRequest($request);

        $tokenId = $authorization->getAttribute('oauth_access_token_id');
        $scopes = $authorization->getAttribute('oauth_scopes');

        $accessToken = $this->accessTokenRepository->findById($tokenId);
        if (!$accessToken instanceof AccessTokenEntity) {
            throw new UserNotFound('Access token not found');
        }
        $user = $this->getUser($accessToken);

        $claims = $this->claimTranslatorExtractor->extract($scopes, $user->getClaims());
        $requestedClaims =  $accessToken->getRequestedClaims();
        $additionalClaims = $this->claimTranslatorExtractor->extractAdditionalUserInfoClaims(
            $requestedClaims,
            $user->getClaims()
        );
        $claims = array_merge($additionalClaims, $claims);

        return new JsonResponse($claims);
    }

    /**
     * @param AccessTokenEntity $accessToken
     *
     * @throws UserNotFound
     *
     * @return UserEntity
     */
    private function getUser(AccessTokenEntity $accessToken)
    {
        $userIdentifier = (string) $accessToken->getUserIdentifier();
        $user = $this->userRepository->getUserEntityByIdentifier($userIdentifier);
        if (!$user instanceof UserEntity) {
            throw new UserNotFound("User ${userIdentifier} not found");
        }

        return $user;
    }
}
