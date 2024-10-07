<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Entities;

use DateTimeImmutable;
use DateTimeZone;
use PDO;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Entities\AuthCodeEntity;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;

/**
 * @covers \SimpleSAML\Module\oidc\Entities\AuthCodeEntity
 */
class AuthCodeEntityTest extends TestCase
{
    protected MockObject $clientEntityMock;
    protected array $state;
    protected string $id;
    protected Stub $scopeEntityOpenIdStub;
    protected array $scopes;
    protected string $userIdentifier;
    protected bool $isRevoked;
    protected string $redirectUri;
    protected string $nonce;
    protected DateTimeImmutable $expiryDateTime;

    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->clientEntityMock = $this->createMock(ClientEntity::class);
        $this->clientEntityMock->method('getIdentifier')->willReturn('client_id');

        $this->id = 'id';

        $this->scopeEntityOpenIdStub = $this->createStub(ScopeEntity::class);
        $this->scopeEntityOpenIdStub->method('getIdentifier')->willReturn('openid');
        $this->scopeEntityOpenIdStub->method('jsonSerialize')->willReturn('openid');

        $this->scopes = [$this->scopeEntityOpenIdStub];
        $this->expiryDateTime = new DateTimeImmutable('1970-01-01 00:00:00', new DateTimeZone('UTC'));
        $this->userIdentifier = 'user_id';
        $this->isRevoked = false;
        $this->redirectUri = 'https://localhost/redirect';
        $this->nonce = 'nonce';
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    protected function mock(): AuthCodeEntity
    {
        return new AuthCodeEntity(
            $this->id,
            $this->clientEntityMock,
            $this->scopes,
            $this->expiryDateTime,
            $this->userIdentifier,
            $this->redirectUri,
            $this->nonce,
            $this->isRevoked,
        );
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            AuthCodeEntity::class,
            $this->mock(),
        );
    }

    /**
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCanGetState(): void
    {
        $this->assertSame(
            $this->mock()->getState(),
            [
                'id' => 'id',
                'scopes' => '["openid"]',
                'expires_at' => '1970-01-01 00:00:00',
                'user_id' => 'user_id',
                'client_id' => 'client_id',
                'is_revoked' => [false, PDO::PARAM_BOOL],
                'redirect_uri' => 'https://localhost/redirect',
                'nonce' => 'nonce',
            ],
        );
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testCanSetNonce(): void
    {
        $authCodeEntity = $this->mock();
        $this->assertSame('nonce', $authCodeEntity->getNonce());
        $authCodeEntity->setNonce('new_nonce');
        $this->assertSame('new_nonce', $authCodeEntity->getNonce());
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testCanBeRevoked(): void
    {
        $authCodeEntity = $this->mock();
        $this->assertSame(false, $authCodeEntity->isRevoked());
        $authCodeEntity->revoke();
        $this->assertSame(true, $authCodeEntity->isRevoked());
    }
}
