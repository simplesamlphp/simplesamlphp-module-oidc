<?php

namespace SimpleSAML\Test\Module\oidc\Entity;

use SimpleSAML\Module\oidc\Entity\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entity\Interfaces\RefreshTokenEntityInterface;
use SimpleSAML\Module\oidc\Entity\RefreshTokenEntity;
use PHPUnit\Framework\TestCase;

/**
 * @covers \SimpleSAML\Module\oidc\Entity\RefreshTokenEntity
 */
class RefreshTokenEntityTest extends TestCase
{
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $accessTokenEntityMock;
    protected array $state;

    protected function setUp(): void
    {
        $this->accessTokenEntityMock = $this->createMock(AccessTokenEntity::class);
        $this->accessTokenEntityMock->method('getIdentifier')->willReturn('access_token_id');

        $this->state = [
            'id' => 'id',
            'expires_at' => '1970-01-01 00:00:00',
            'access_token' => $this->accessTokenEntityMock,
            'is_revoked' => false,
            'auth_code_id' => '123',
        ];
    }

    protected function prepareMockedInstance(array $state = null): RefreshTokenEntityInterface
    {
        $state = $state ?? $this->state;
        return RefreshTokenEntity::fromState($state);
    }

    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            RefreshTokenEntity::class,
            $this->prepareMockedInstance()
        );
    }

    public function testCanGetState(): void
    {
        $this->assertSame(
            $this->prepareMockedInstance()->getState(),
            [
                'id' => 'id',
                'expires_at' => '1970-01-01 00:00:00',
                'access_token_id' => 'access_token_id',
                'is_revoked' => 0,
                'auth_code_id' => '123',
            ]
        );
    }
}
