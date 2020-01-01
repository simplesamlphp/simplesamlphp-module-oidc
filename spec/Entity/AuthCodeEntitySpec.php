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

namespace spec\SimpleSAML\Modules\OpenIDConnect\Entity;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use PhpSpec\ObjectBehavior;
use SimpleSAML\Modules\OpenIDConnect\Entity\AuthCodeEntity;
use SimpleSAML\Modules\OpenIDConnect\Entity\Interfaces\MementoInterface;

class AuthCodeEntitySpec extends ObjectBehavior
{
    /**
     * @return void
     */
    public function let(ClientEntityInterface $clientEntity)
    {
        $clientEntity->getIdentifier()->willReturn('client_id');

        $this->beConstructedThrough('fromState', [
            [
                'id' => 'id',
                'scopes' => json_encode([]),
                'expires_at' => '1970-01-01 00:00:00',
                'user_id' => 'user_id',
                'client' => $clientEntity,
                'is_revoked' => false,
                'redirect_uri' => 'https://localhost/redirect',
            ],
        ]);
    }

    /**
     * @return void
     */
    public function it_is_initializable()
    {
        $this->shouldHaveType(AuthCodeEntity::class);
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
    public function it_has_scopes()
    {
        $this->getScopes()->shouldBeEqualTo([]);
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
    public function it_has_an_user_id()
    {
        $this->getUserIdentifier()->shouldBeEqualTo('user_id');
    }

    /**
     * @return void
     */
    public function it_has_a_client(ClientEntityInterface $clientEntity)
    {
        $this->getClient()->shouldBe($clientEntity);
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
    public function it_has_a_redirect_uri()
    {
        $this->getRedirectUri()->shouldBeEqualTo('https://localhost/redirect');
    }

    /**
     * @return void
     */
    public function it_can_return_state()
    {
        $this->getState()->shouldBeLike([
            'id' => 'id',
            'scopes' => json_encode([]),
            'expires_at' => '1970-01-01 00:00:00',
            'user_id' => 'user_id',
            'client_id' => 'client_id',
            'is_revoked' => false,
            'redirect_uri' => 'https://localhost/redirect',
        ]);
    }
}
