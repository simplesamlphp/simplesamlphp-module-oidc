<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Entities;

use Exception;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;

/**
 * @covers \SimpleSAML\Module\oidc\Entities\UserEntity
 */
class UserEntityTest extends TestCase
{
    protected array $state;

    protected function setUp(): void
    {
        $this->state = [
            'id' => 'id',
            'claims' => json_encode([]),
            'updated_at' => '1970-01-01 00:00:00',
            'created_at' => '1970-01-01 00:00:00',
        ];
    }

    /**
     * @throws OidcServerException
     */
    protected function prepareMockedInstance(array $state = null): UserEntity
    {
        $state ??= $this->state;
        return UserEntity::fromState($state);
    }

    /**
     * @throws OidcServerException
     * @throws Exception
     */
    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            UserEntity::class,
            $this->prepareMockedInstance()
        );

        $this->assertInstanceOf(
            UserEntity::class,
            UserEntity::fromData('id')
        );
    }

    /**
     * @throws OidcServerException
     * @throws Exception
     */
    public function testCanGetProperties(): void
    {
        $userEntity = $this->prepareMockedInstance();
        $this->assertSame($userEntity->getIdentifier(), 'id');
        $this->assertSame($userEntity->getClaims(), []);
        $this->assertSame($userEntity->getCreatedAt()->format('Y-m-d H:i:s'), '1970-01-01 00:00:00');
        $this->assertSame($userEntity->getUpdatedAt()->format('Y-m-d H:i:s'), '1970-01-01 00:00:00');

        $userEntity->setClaims(['claim']);
        $this->assertSame($userEntity->getClaims(), ['claim']);
    }

    /**
     * @throws OidcServerException
     */
    public function testCanGetState(): void
    {
        $this->assertSame(
            $this->prepareMockedInstance()->getState(),
            [
                'id' => 'id',
                'claims' => json_encode([]),
                'updated_at' => '1970-01-01 00:00:00',
                'created_at' => '1970-01-01 00:00:00',
            ]
        );
    }
}
