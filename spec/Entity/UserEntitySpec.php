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

use PhpSpec\ObjectBehavior;
use SimpleSAML\Module\oidc\Entity\Interfaces\MementoInterface;
use SimpleSAML\Module\oidc\Entity\UserEntity;

class UserEntitySpec extends ObjectBehavior
{
    /**
     * @return void
     */
    public function let()
    {
        $this->beConstructedThrough('fromState', [
            [
                'id' => 'id',
                'claims' => json_encode([]),
                'updated_at' => '1970-01-01 00:00:00',
                'created_at' => '1970-01-01 00:00:00',
            ],
        ]);
    }

    /**
     * @return void
     */
    public function it_is_initializable()
    {
        $this->shouldHaveType(UserEntity::class);
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
        $this->getIdentifier()->shouldBeLike('id');
    }

    /**
     * @return void
     */
    public function it_has_claims()
    {
        $this->getClaims()->shouldBeLike([]);
    }

    /**
     * @return void
     */
    public function it_has_created_date_time()
    {
        $this->getCreatedAt()->format('Y-m-d H:i:s')->shouldBeLike('1970-01-01 00:00:00');
    }

    /**
     * @return void
     */
    public function it_has_updated_date_time()
    {
        $this->getUpdatedAt()->format('Y-m-d H:i:s')->shouldBeLike('1970-01-01 00:00:00');
    }

    /**
     * @return void
     */
    public function it_can_return_state()
    {
        $this->getState()->shouldBeLike([
            'id' => 'id',
            'claims' => json_encode([]),
            'updated_at' => '1970-01-01 00:00:00',
            'created_at' => '1970-01-01 00:00:00',
        ]);
    }
}
