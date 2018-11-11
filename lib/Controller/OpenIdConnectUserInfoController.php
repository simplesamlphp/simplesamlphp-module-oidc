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

namespace SimpleSAML\Modules\OpenIDConnect\Controller;

use League\OAuth2\Server\ResourceServer;
use SimpleSAML\Modules\OpenIDConnect\ClaimTranslatorExtractor;
use SimpleSAML\Modules\OpenIDConnect\Repositories\AccessTokenRepository;
use SimpleSAML\Modules\OpenIDConnect\Repositories\UserRepository;
use Zend\Diactoros\Response\JsonResponse;
use Zend\Diactoros\ServerRequest;

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

    public function __invoke(ServerRequest $request)
    {
        $authorization = $this->resourceServer->validateAuthenticatedRequest($request);

        $tokenId = $authorization->getAttribute('oauth_access_token_id');
        $scopes = $authorization->getAttribute('oauth_scopes');

        $accessToken = $this->accessTokenRepository->findById($tokenId);

        $user = $this->userRepository->getUserEntityByIdentifier($accessToken->getUserIdentifier());
        $claims = $this->claimTranslatorExtractor->extract($scopes, $user->getClaims());

        return new JsonResponse($claims);
    }
}
