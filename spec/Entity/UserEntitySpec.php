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

use PhpSpec\ObjectBehavior;
use SimpleSAML\Modules\OpenIDConnect\Entity\Interfaces\MementoInterface;
use SimpleSAML\Modules\OpenIDConnect\Entity\UserEntity;

class UserEntitySpec extends ObjectBehavior
{
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

    public function it_is_initializable()
    {
        $this->shouldHaveType(UserEntity::class);
    }

    public function it_implements_memento_interface()
    {
        $this->shouldHaveType(MementoInterface::class);
    }

    public function it_has_an_id()
    {
        $this->getIdentifier()->shouldBeLike('id');
    }

    public function it_has_claims()
    {
        $this->getClaims()->shouldBeLike([]);
    }

    public function it_has_created_date_time()
    {
        $this->getCreatedAt()->format('Y-m-d H:i:s')->shouldBeLike('1970-01-01 00:00:00');
    }

    public function it_has_updated_date_time()
    {
        $this->getUpdatedAt()->format('Y-m-d H:i:s')->shouldBeLike('1970-01-01 00:00:00');
    }

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
