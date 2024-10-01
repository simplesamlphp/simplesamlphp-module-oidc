<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Entities;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;

/**
 * @covers \SimpleSAML\Module\oidc\Entities\AccessTokenEntity
 *
 * @backupGlobals enabled
 */
class AccessTokenEntityTest extends TestCase
{
    protected array $state;

    protected string $id = '123';
    protected array $scopes;
    protected string $expiresAt;
    protected string $userId = 'user123';
    protected bool $isRevoked = false;
    protected string $authCodeId = 'authCode123';
    protected array $requestedClaims = ['key' => 'value'];
    protected string $clientId = 'client123';


    /**
     * @var \SimpleSAML\Module\oidc\Entities\ClientEntity
     */
    protected ClientEntity $clientEntityStub;

    /**
     * @var \SimpleSAML\Module\oidc\Entities\ScopeEntity
     */
    protected ScopeEntity $scopeEntityOpenId;

    /**
     * @var \SimpleSAML\Module\oidc\Entities\ScopeEntity
     */
    protected ScopeEntity $scopeEntityProfile;

    /**
     * @throws \Exception
     * @throws \JsonException
     */
    protected function setUp(): void
    {
        // Plant certdir config for JsonWebTokenBuilderService (since we don't inject it)
        Configuration::clearInternalState();
        $config = [
            'certdir' => dirname(__DIR__, 4) . '/docker/ssp/',
        ];
        Configuration::loadFromArray($config, '', 'simplesaml');

        $this->clientEntityStub = $this->createStub(ClientEntity::class);
        $this->clientEntityStub->method('getIdentifier')->willReturn($this->clientId);

        $this->scopeEntityOpenId = $this->createStub(ScopeEntity::class);
        $this->scopeEntityOpenId->method('getIdentifier')->willReturn('openid');
        $this->scopeEntityOpenId->method('jsonSerialize')->willReturn('openid');
        $this->scopeEntityProfile = $this->createStub(ScopeEntity::class);
        $this->scopeEntityProfile->method('getIdentifier')->willReturn('profile');
        $this->scopeEntityProfile->method('jsonSerialize')->willReturn('profile');

        $this->scopes = [$this->scopeEntityOpenId, $this->scopeEntityProfile,];

        $this->expiresAt = date('Y-m-d H:i:s', strtotime('+10 minutes'));
    }

    public function mock(): AccessTokenEntity
    {
        return new AccessTokenEntity(
            $this->clientEntityStub,
            $this->scopes,
            $this->userId,
            $this->authCodeId,
            $this->requestedClaims,
        );
    }

    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(
            AccessTokenEntity::class,
            $this->mock(),
        );
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testHasProperState(): void
    {
        $accessTokenEntityState = $this->mock()->getState();

        $this->assertSame($this->id, $accessTokenEntityState['id']);
        $this->assertSame(json_encode($this->scopes, JSON_THROW_ON_ERROR), $accessTokenEntityState['scopes']);

        $this->assertSame($this->requestedClaims, $this->mock()->getRequestedClaims());
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testHasImmutableStringRepresentation(): void
    {
        $this->assertNull($this->mock()->toString());

        $stringRepresentation = (string) $this->mock();

        $this->assertIsString($this->mock()->toString());

        $this->assertSame($stringRepresentation, $this->mock()->toString());
    }
}
