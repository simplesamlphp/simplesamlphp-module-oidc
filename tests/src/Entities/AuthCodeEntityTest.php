<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Entities;

use JsonException;
use PHPUnit\Framework\MockObject\Exception;
use PHPUnit\Framework\MockObject\MockObject;
use SimpleSAML\Module\oidc\Entities\AuthCodeEntity;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;

/**
 * @covers \SimpleSAML\Module\oidc\Entities\AuthCodeEntity
 */
class AuthCodeEntityTest extends TestCase
{
    protected MockObject $clientEntityMock;
    protected array $state;

    /**
     * @throws Exception
     */
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
            'nonce' => 'nonce',
        ];
    }

    /**
     * @throws OidcServerException
     * @throws JsonException
     */
    protected function prepareMockedInstance(array $state = null): AuthCodeEntity
    {
        $state ??= $this->state;
        return AuthCodeEntity::fromState($state);
    }

    /**
     * @throws OidcServerException
     * @throws JsonException
     */
    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            AuthCodeEntity::class,
            $this->prepareMockedInstance(),
        );
    }

    /**
     * @throws JsonException
     * @throws OidcServerException
     */
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
            ],
        );
    }

    /**
     * @throws OidcServerException
     * @throws JsonException
     */
    public function testCanSetNonce(): void
    {
        $authCodeEntity = $this->prepareMockedInstance();
        $this->assertSame('nonce', $authCodeEntity->getNonce());
        $authCodeEntity->setNonce('new_nonce');
        $this->assertSame('new_nonce', $authCodeEntity->getNonce());
    }

    /**
     * @throws OidcServerException
     * @throws JsonException
     */
    public function testCanBeRevoked(): void
    {
        $authCodeEntity = $this->prepareMockedInstance();
        $this->assertSame(false, $authCodeEntity->isRevoked());
        $authCodeEntity->revoke();
        $this->assertSame(true, $authCodeEntity->isRevoked());
    }
}
