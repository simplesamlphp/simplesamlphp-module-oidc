<?php

namespace SimpleSAML\Test\Module\oidc\Entity;

use SimpleSAML\Module\oidc\Entity\UserEntity;
use PHPUnit\Framework\TestCase;

/**
 * @covers \SimpleSAML\Module\oidc\Entity\UserEntity
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

    protected function prepareMockedInstance(array $state = null): UserEntity
    {
        $state = $state ?? $this->state;
        return UserEntity::fromState($state);
    }

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
