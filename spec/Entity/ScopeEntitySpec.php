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
use SimpleSAML\Modules\OpenIDConnect\Entity\ScopeEntity;

class ScopeEntitySpec extends ObjectBehavior
{
    public function let()
    {
        $this->beConstructedThrough('fromData', [
            'id',
            'description',
            'icon',
            ['attrid' => 'attrval'],
        ]);
    }

    public function it_is_initializable()
    {
        $this->shouldHaveType(ScopeEntity::class);
    }

    public function it_has_an_id()
    {
        $this->getIdentifier()->shouldBeLike('id');
    }

    public function it_has_an_icon()
    {
        $this->getIcon()->shouldBeLike('icon');
    }

    public function it_has_a_description()
    {
        $this->getDescription()->shouldBeLike('description');
    }

    public function it_has_attributes()
    {
        $this->getAttributes()->shouldBeLike(['attrid' => 'attrval']);
    }

    public function it_is_serializable()
    {
        $this->jsonSerialize()->shouldBeLike('id');
    }
}
