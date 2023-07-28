<?php

namespace SimpleSAML\Test\Module\oidc\Entity;

use SimpleSAML\Module\oidc\Entity\ClientEntity;
use PHPUnit\Framework\TestCase;

/**
 * @covers \SimpleSAML\Module\oidc\Entity\ClientEntity
 */
class ClientEntityTest extends TestCase
{
    protected array $state;
    protected function setUp(): void
    {
        $this->state = [
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
            'backchannel_logout_uri' => null,
        ];
    }

    public function prepareMockedInstance(array $state = null): ClientEntity
    {
        $state = $state ?? $this->state;
        return ClientEntity::fromState($state);
    }

    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            ClientEntity::class,
            $this->prepareMockedInstance()
        );

        $this->assertInstanceOf(
            ClientEntity::class,
            ClientEntity::fromData('id', 'secret', 'name', 'description', ['redirectUri'], [], true)
        );
    }

    public function testCanGetProperties(): void
    {
        $clientEntity = $this->prepareMockedInstance();

        $this->assertSame('id', $clientEntity->getIdentifier());
        $this->assertSame('secret', $clientEntity->getSecret());
        $this->assertSame('description', $clientEntity->getDescription());
        $this->assertSame('auth_source', $clientEntity->getAuthSourceId());
        $this->assertSame(['https://localhost/redirect'], $clientEntity->getRedirectUri());
        $this->assertSame([], $clientEntity->getScopes());
        $this->assertSame(true, $clientEntity->isEnabled());
        $this->assertSame(false, $clientEntity->isConfidential());
        $this->assertSame([], $clientEntity->getPostLogoutRedirectUri());
        $this->assertSame(null, $clientEntity->getBackChannelLogoutUri());

        $clientEntity->restoreSecret('new_secret');
        $this->assertSame($clientEntity->getSecret(), 'new_secret');
        $clientEntity->setPostLogoutRedirectUri(['https://localhost/post']);
        $this->assertSame(['https://localhost/post'], $clientEntity->getPostLogoutRedirectUri());
        $clientEntity->setBackChannelLogoutUri('https://localhost/back');
        $this->assertSame('https://localhost/back', $clientEntity->getBackChannelLogoutUri());
    }

    public function testCanChangeSecret(): void
    {
        $clientEntity = $this->prepareMockedInstance();
        $this->assertSame('secret', $clientEntity->getSecret());
        $clientEntity->restoreSecret('new_secret');
        $this->assertSame($clientEntity->getSecret(), 'new_secret');
    }

    public function testCanGetState(): void
    {
        $this->assertSame(
            $this->prepareMockedInstance()->getState(),
            [
                'id' => 'id',
                'secret' => 'secret',
                'name' => 'name',
                'description' => 'description',
                'auth_source' => 'auth_source',
                'redirect_uri' => json_encode(['https://localhost/redirect']),
                'scopes' => json_encode([]),
                'is_enabled' => 1,
                'is_confidential' => 0,
                'owner' => 'user@test.com',
                'post_logout_redirect_uri' => json_encode([]),
                'backchannel_logout_uri' => null,
            ]
        );
    }

    public function testCanExportAsArray(): void
    {
        $this->assertSame(
            $this->prepareMockedInstance()->toArray(),
            [
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
                'backchannel_logout_uri' => null,
            ]
        );
    }
}
