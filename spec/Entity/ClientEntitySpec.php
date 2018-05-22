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
use SimpleSAML\Modules\OpenIDConnect\Entity\ClientEntity;
use SimpleSAML\Modules\OpenIDConnect\Entity\Interfaces\MementoInterface;

class ClientEntitySpec extends ObjectBehavior
{
    public function let(ClientEntityInterface $clientEntity)
    {
        $clientEntity->getIdentifier()->willReturn('client_id');

        $this->beConstructedThrough('fromState', [
            [
                'id' => 'id',
                'secret' => 'secret',
                'name' => 'name',
                'description' => 'description',
                'auth_source' => 'auth_source',
                'redirect_uri' => \json_encode(['https://localhost/redirect']),
                'scopes' => json_encode([]),
                'is_enabled' => true,
            ],
        ]);
    }

    public function it_is_initializable()
    {
        $this->shouldHaveType(ClientEntity::class);
    }

    public function it_implements_memento_interface()
    {
        $this->shouldHaveType(MementoInterface::class);
    }

    public function it_has_an_id()
    {
        $this->getIdentifier()->shouldBeLike('id');
    }

    public function it_has_a_secret()
    {
        $this->getSecret()->shouldBeLike('secret');
    }

    public function its_secret_can_be_changed()
    {
        $this->restoreSecret('new_secret');
        $this->getSecret()->shouldBeLike('new_secret');
    }

    public function it_has_a_description()
    {
        $this->getDescription()->shouldBeLike('description');
    }

    public function it_has_an_auth_source()
    {
        $this->getAuthSource()->shouldBeLike('auth_source');
    }

    public function it_has_direct_uris()
    {
        $this->getRedirectUri()->shouldBeLike(['https://localhost/redirect']);
    }

    public function it_has_scopes()
    {
        $this->getScopes()->shouldBeLike([]);
    }

    public function it_can_be_enabled()
    {
        $this->isEnabled()->shouldBeEqualTo(true);
    }

    public function it_can_return_state()
    {
        $this->getState()->shouldBeLike([
            'id' => 'id',
            'secret' => 'secret',
            'name' => 'name',
            'description' => 'description',
            'auth_source' => 'auth_source',
            'redirect_uri' => \json_encode(['https://localhost/redirect']),
            'scopes' => json_encode([]),
            'is_enabled' => true,
        ]);
    }

    public function it_can_be_exported_as_array()
    {
        $this->toArray()->shouldBeLike([
            'id' => 'id',
            'secret' => 'secret',
            'name' => 'name',
            'description' => 'description',
            'auth_source' => 'auth_source',
            'redirect_uri' => ['https://localhost/redirect'],
            'scopes' => [],
            'is_enabled' => true,
        ]);
    }
}
