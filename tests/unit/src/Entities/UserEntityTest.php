<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Entities;

use DateTimeImmutable;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Entities\UserEntity;

/**
 * @covers \SimpleSAML\Module\oidc\Entities\UserEntity
 */
class UserEntityTest extends TestCase
{
    protected array $state;

    protected string $identifier = 'id';

    protected array $claims = [];

    protected Stub $createdAt;
    protected Stub $updatedAt;

    protected function setUp(): void
    {
        $this->state = [
            'id' => 'id',
            'claims' => json_encode([]),
            'updated_at' => '1970-01-01 00:00:00',
            'created_at' => '1970-01-01 00:00:00',
        ];

        $this->createdAt = $this->createStub(DateTimeImmutable::class);
        $this->updatedAt = $this->createStub(DateTimeImmutable::class);
    }

    protected function mock(
        ?string $identifier = null,
        ?array $claims = null,
        ?Stub $createdAt = null,
        ?Stub $updatedAt = null,
    ): UserEntity {
        $identifier ??= $this->identifier;
        $claims ??= $this->claims;
        $createdAt ??= $this->createdAt;
        $updatedAt ??= $this->updatedAt;

        return new UserEntity(
            $identifier,
            $createdAt,
            $updatedAt,
            $claims,
        );
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Exception
     */
    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            UserEntity::class,
            $this->mock(),
        );
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Exception
     */
    public function testCanGetProperties(): void
    {
        $userEntity = $this->mock();
        $this->assertSame($userEntity->getIdentifier(), 'id');
        $this->assertSame($userEntity->getClaims(), []);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCanGetState(): void
    {
        $this->assertSame(
            $this->mock()->getState(),
            [
                'id' => 'id',
                'claims' => json_encode([]),
                'updated_at' => '',
                'created_at' => '',
            ],
        );
    }
}
