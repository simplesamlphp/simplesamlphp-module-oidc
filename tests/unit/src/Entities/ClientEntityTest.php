<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Entities;

use PDO;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Entities\ClientEntity;

/**
 * @covers \SimpleSAML\Module\oidc\Entities\ClientEntity
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

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function prepareMockedInstance(array $state = null): ClientEntity
    {
        $state ??= $this->state;
        return ClientEntity::fromState($state);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            ClientEntity::class,
            $this->prepareMockedInstance(),
        );

        $this->assertInstanceOf(
            ClientEntity::class,
            ClientEntity::fromData('id', 'secret', 'name', 'description', ['redirectUri'], [], true),
        );
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
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

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testCanChangeSecret(): void
    {
        $clientEntity = $this->prepareMockedInstance();
        $this->assertSame('secret', $clientEntity->getSecret());
        $clientEntity->restoreSecret('new_secret');
        $this->assertSame($clientEntity->getSecret(), 'new_secret');
    }

    /**
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
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
                'is_enabled' => [$this->state['is_enabled'], PDO::PARAM_BOOL],
                'is_confidential' => [$this->state['is_confidential'], PDO::PARAM_BOOL],
                'owner' => 'user@test.com',
                'post_logout_redirect_uri' => json_encode([]),
                'backchannel_logout_uri' => null,
                'entity_identifier' => null,
                'client_registration_types' => null,
                'federation_jwks' => null,
                'jwks' => null,
                'jwks_uri' => null,
                'signed_jwks_uri' => null,
            ],
        );
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
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
                'entity_identifier' => null,
                'client_registration_types' => null,
                'federation_jwks' => null,
                'jwks' => null,
                'jwks_uri' => null,
                'signed_jwks_uri' => null,
            ],
        );
    }
}
