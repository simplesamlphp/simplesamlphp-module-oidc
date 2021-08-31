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

namespace spec\SimpleSAML\Module\oidc\Controller;

use Laminas\Diactoros\Response\JsonResponse;
use Laminas\Diactoros\ServerRequest;
use League\OAuth2\Server\ResourceServer;
use PhpSpec\ObjectBehavior;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Controller\OpenIdConnectUserInfoController;
use SimpleSAML\Module\oidc\Entity\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entity\UserEntity;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;

class OpenIdConnectUserInfoControllerSpec extends ObjectBehavior
{
    /**
     * @return void
     */
    public function let(
        ResourceServer $resourceServer,
        AccessTokenRepository $accessTokenRepository,
        UserRepository $userRepository,
        AllowedOriginRepository $allowedOriginRepository,
        ClaimTranslatorExtractor $claimTranslatorExtractor
    ) {
        $this->beConstructedWith(
            $resourceServer,
            $accessTokenRepository,
            $userRepository,
            $allowedOriginRepository,
            $claimTranslatorExtractor
        );
    }

    /**
     * @return void
     */
    public function it_is_initializable()
    {
        $this->shouldHaveType(OpenIdConnectUserInfoController::class);
    }

    /**
     * @return void
     */
    public function it_returns_user_claims(
        ServerRequest $request,
        ServerRequestInterface $authorization,
        ResourceServer $resourceServer,
        AccessTokenRepository $accessTokenRepository,
        AccessTokenEntity $accessTokenEntity,
        UserRepository $userRepository,
        UserEntity $userEntity,
        ClaimTranslatorExtractor $claimTranslatorExtractor
    ) {
        $request->getMethod()->shouldBeCalled()->willReturn('GET');
        $resourceServer->validateAuthenticatedRequest($request)->shouldBeCalled()->willReturn($authorization);
        $authorization->getAttribute('oauth_access_token_id')->shouldBeCalled()->willReturn('tokenid');
        $authorization->getAttribute('oauth_scopes')->shouldBeCalled()->willReturn(['openid', 'email']);

        $accessTokenRepository->findById('tokenid')->shouldBeCalled()->willReturn($accessTokenEntity);
        $accessTokenEntity->getUserIdentifier()->shouldBeCalled()->willReturn('userid');
        $accessTokenEntity->getRequestedClaims()->shouldBeCalled()->willReturn([]);
        $userRepository->getUserEntityByIdentifier('userid')->shouldBeCalled()->willReturn($userEntity);
        $userEntity->getClaims()->shouldBeCalled()->willReturn(['mail' => ['userid@localhost.localdomain']]);
        $claimTranslatorExtractor
            ->extract(['openid', 'email'], ['mail' => ['userid@localhost.localdomain']])
            ->shouldBeCalled()->willReturn(['email' => 'userid@localhost.localdomain']);
        $claimTranslatorExtractor->extractAdditionalUserInfoClaims([], ['mail' => ['userid@localhost.localdomain']])
            ->shouldBeCalledOnce()->willReturn([]);


        $this->__invoke($request)->shouldHavePayload(['email' => 'userid@localhost.localdomain']);
    }

    public function getMatchers(): array
    {
        return [
            'havePayload' => function (JsonResponse $subject, $payload) {
                return $payload === $subject->getPayload();
            },
        ];
    }
}
