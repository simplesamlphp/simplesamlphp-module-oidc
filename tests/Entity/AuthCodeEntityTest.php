<?php

namespace SimpleSAML\Test\Module\oidc\Entity;

use SimpleSAML\Module\oidc\Entity\AuthCodeEntity;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Entity\ClientEntity;

/**
 * @covers \SimpleSAML\Module\oidc\Entity\AuthCodeEntity
 */
class AuthCodeEntityTest extends TestCase
{
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $clientEntityMock;
    protected array $state;

    protected function setUp(): void
    {
        $this->clientEntityMock = $this->createMock(ClientEntity::class);
        $this->clientEntityMock->method('getIdentifier')->willReturn('client_id');
        $this->state = [
            'id' => 'id',
            'scopes' => json_encode(['openid']),
            'expires_at' => '1970-01-01 00:00:00',
            'user_id' => 'user_id',
            'client' => $this->clientEntityMock,
            'is_revoked' => false,
            'redirect_uri' => 'https://localhost/redirect',
            'nonce' => 'nonce'
        ];
    }

    protected function prepareMockedInstance(array $state = null): AuthCodeEntity
    {
        $state = $state ?? $this->state;
        return AuthCodeEntity::fromState($state);
    }

    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            AuthCodeEntity::class,
            $this->prepareMockedInstance()
        );
    }

    public function testCanGetState(): void
    {
        $this->assertSame(
            $this->prepareMockedInstance()->getState(),
            [
                'id' => 'id',
                'scopes' => '["openid"]',
                'expires_at' => '1970-01-01 00:00:00',
                'user_id' => 'user_id',
                'client_id' => 'client_id',
                'is_revoked' => 0,
                'redirect_uri' => 'https://localhost/redirect',
                'nonce' => 'nonce',
            ]
        );
    }

    public function testCanSetNonce(): void
    {
        $authCodeEntity = $this->prepareMockedInstance();
        $this->assertSame('nonce', $authCodeEntity->getNonce());
        $authCodeEntity->setNonce('new_nonce');
        $this->assertSame('new_nonce', $authCodeEntity->getNonce());
    }

    public function testCanBeRevoked(): void
    {
        $authCodeEntity = $this->prepareMockedInstance();
        $this->assertSame(false, $authCodeEntity->isRevoked());
        $authCodeEntity->revoke();
        $this->assertSame(true, $authCodeEntity->isRevoked());
    }
}
