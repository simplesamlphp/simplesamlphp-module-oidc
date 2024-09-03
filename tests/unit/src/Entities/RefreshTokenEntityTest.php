<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Entities;

use PDO;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\RefreshTokenEntityInterface;
use SimpleSAML\Module\oidc\Entities\RefreshTokenEntity;

/**
 * @covers \SimpleSAML\Module\oidc\Entities\RefreshTokenEntity
 */
class RefreshTokenEntityTest extends TestCase
{
    protected MockObject $accessTokenEntityMock;
    protected array $state;

    /**
     * @throws \Exception
     */
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

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    protected function prepareMockedInstance(array $state = null): RefreshTokenEntityInterface
    {
        $state ??= $this->state;
        return RefreshTokenEntity::fromState($state);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            RefreshTokenEntity::class,
            $this->prepareMockedInstance(),
        );
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCanGetState(): void
    {
        $this->assertSame(
            $this->prepareMockedInstance()->getState(),
            [
                'id' => 'id',
                'expires_at' => '1970-01-01 00:00:00',
                'access_token_id' => 'access_token_id',
                'is_revoked' => [$this->state['is_revoked'], PDO::PARAM_BOOL],
                'auth_code_id' => '123',
            ],
        );
    }
}
