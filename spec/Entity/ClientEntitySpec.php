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

use League\OAuth2\Server\Entities\ClientEntityInterface;
use PhpSpec\ObjectBehavior;
use SimpleSAML\Module\oidc\Entity\ClientEntity;
use SimpleSAML\Module\oidc\Entity\Interfaces\MementoInterface;

class ClientEntitySpec extends ObjectBehavior
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
                'secret' => 'secret',
                'name' => 'name',
                'description' => 'description',
                'auth_source' => 'auth_source',
                'redirect_uri' => json_encode(['https://localhost/redirect']),
                'scopes' => json_encode([]),
                'is_enabled' => true,
                'is_confidential' => false,
                'owner' => 'user@test.com',
                'post_logout_redirect_uri' => json_encode([]),
            ],
        ]);
    }

    /**
     * @return void
     */
    public function it_is_initializable()
    {
        $this->shouldHaveType(ClientEntity::class);
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
    public function it_has_a_secret()
    {
        $this->getSecret()->shouldBeLike('secret');
    }

    /**
     * @return void
     */
    public function its_secret_can_be_changed()
    {
        $this->restoreSecret('new_secret');
        $this->getSecret()->shouldBeLike('new_secret');
    }

    /**
     * @return void
     */
    public function it_has_a_description()
    {
        $this->getDescription()->shouldBeLike('description');
    }

    /**
     * @return void
     */
    public function it_has_an_auth_source()
    {
        $this->getAuthSource()->shouldBeLike('auth_source');
    }

    /**
     * @return void
     */
    public function it_has_direct_uris()
    {
        $this->getRedirectUri()->shouldBeLike(['https://localhost/redirect']);
    }

    /**
     * @return void
     */
    public function it_has_scopes()
    {
        $this->getScopes()->shouldBeLike([]);
    }

    /**
     * @return void
     */
    public function it_can_be_enabled()
    {
        $this->isEnabled()->shouldBeEqualTo(true);
    }

    /**
     * @return void
     */
    public function it_can_be_confidential()
    {
        $this->isConfidential()->shouldBeEqualTo(false);
    }

    /**
     * @return void
     */
    public function it_can_return_post_logout_redirect_uri()
    {
        $this->getPostLogoutRedirectUri()->shouldBeEqualTo([]);
    }

    /**
     * @return void
     */
    public function it_can_return_state()
    {
        $this->getState()->shouldBeLike([
            'id' => 'id',
            'secret' => 'secret',
            'name' => 'name',
            'description' => 'description',
            'auth_source' => 'auth_source',
            'redirect_uri' => json_encode(['https://localhost/redirect']),
            'scopes' => json_encode([]),
            'is_enabled' => true,
            'is_confidential' => false,
            'owner' => 'user@test.com',
            'post_logout_redirect_uri' => json_encode([]),
        ]);
    }

    /**
     * @return void
     */
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
            'is_confidential' => false,
            'owner' => 'user@test.com',
            'post_logout_redirect_uri' => [],
        ]);
    }
}
