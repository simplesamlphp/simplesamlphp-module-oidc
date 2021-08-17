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

namespace spec\SimpleSAML\Module\oidc\Entity;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use PhpSpec\ObjectBehavior;
use SimpleSAML\Module\oidc\Entity\Interfaces\MementoInterface;
use SimpleSAML\Module\oidc\Entity\RefreshTokenEntity;

class RefreshTokenEntitySpec extends ObjectBehavior
{
    /**
     * @return void
     */
    public function let(AccessTokenEntityInterface $accessTokenEntity)
    {
        $accessTokenEntity->getIdentifier()->willReturn('access_token_id');

        $this->beConstructedThrough('fromState', [
            [
                'id' => 'id',
                'expires_at' => '1970-01-01 00:00:00',
                'access_token' => $accessTokenEntity,
                'is_revoked' => false,
                'auth_code_id' => '123',
            ],
        ]);
    }

    /**
     * @return void
     */
    public function it_is_initializable()
    {
        $this->shouldHaveType(RefreshTokenEntity::class);
    }

    /**
     * @return void
     */
    public function it_implements_memento_interface()
    {
        $this->shouldHaveType(MementoInterface::class);
    }

    /**
     * @return void
     */
    public function it_has_an_id()
    {
        $this->getIdentifier()->shouldBeEqualTo('id');
    }

    /**
     * @return void
     */
    public function it_has_expiry_date_time()
    {
        $this->getExpiryDateTime()->format('Y-m-d H:i:s')->shouldBeLike('1970-01-01 00:00:00');
    }

    /**
     * @return void
     */
    public function it_has_an_access_token(AccessTokenEntityInterface $accessTokenEntity)
    {
        $this->getAccessToken()->shouldBe($accessTokenEntity);
    }

    /**
     * @return void
     */
    public function it_can_be_revoked()
    {
        $this->isRevoked()->shouldBeEqualTo(false);
    }

    /**
     * @return void
     */
    public function it_has_auth_code_id()
    {
        $this->getAuthCodeId()->shouldBeEqualTo('123');
    }

    /**
     * @return void
     */
    public function it_can_return_state()
    {
        $this->getState()->shouldBeLike([
            'id' => 'id',
            'expires_at' => '1970-01-01 00:00:00',
            'access_token_id' => 'access_token_id',
            'is_revoked' => false,
            'auth_code_id' => '123',
        ]);
    }
}
