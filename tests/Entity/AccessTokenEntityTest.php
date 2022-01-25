<?php

namespace SimpleSAML\Test\Module\oidc\Entity;

use PHPUnit\Framework\MockObject\Stub;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Entity\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entity\ClientEntity;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Entity\ScopeEntity;

/**
 * @covers \SimpleSAML\Module\oidc\Entity\AccessTokenEntity
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
     * @var ClientEntity
     */
    protected ClientEntity $clientEntityStub;

    /**
     * @var ScopeEntity
     */
    protected ScopeEntity $scopeEntityOpenId;

    /**
     * @var ScopeEntity
     */
    protected ScopeEntity $scopeEntityProfile;

    public static function setUpBeforeClass(): void
    {
        // To make lib/SimpleSAML/Utils/HTTP::getSelfURL() work...
        global $_SERVER;
        $_SERVER['REQUEST_URI'] = '';
    }

    protected function setUp(): void
    {
        // Plant certdir config for JsonWebTokenBuilderService (since we don't inject it)
        $config = [
            'certdir' => dirname(__DIR__, 2) . '/docker/ssp/',
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

        $this->state = [
            'id' => $this->id,
            'scopes' => json_encode($this->scopes),
            'expires_at' => $this->expiresAt,
            'user_id' => $this->userId,
            'client' => $this->clientEntityStub,
            'is_revoked' => $this->isRevoked,
            'auth_code_id' => $this->authCodeId,
            'requested_claims' => json_encode($this->requestedClaims)
        ];
    }

    public function testCanCreateInstanceFromState(): void
    {
        $this->assertInstanceOf(AccessTokenEntity::class, AccessTokenEntity::fromState($this->state));
    }

    public function testCanCreateInstanceFromData(): void
    {
        $this->assertInstanceOf(
            AccessTokenEntity::class,
            AccessTokenEntity::fromData(
                $this->clientEntityStub,
                $this->scopes,
                $this->userId,
                $this->authCodeId,
                $this->requestedClaims
            )
        );
    }

    public function testHasProperState(): void
    {
        $accessTokenEntity = AccessTokenEntity::fromState($this->state);
        $accessTokenEntityState = $accessTokenEntity->getState();

        $this->assertSame($this->id, $accessTokenEntityState['id']);
        $this->assertSame(json_encode($this->scopes), $accessTokenEntityState['scopes']);

        $this->assertSame($this->requestedClaims, $accessTokenEntity->getRequestedClaims());
    }

    public function testHasImmutableStringRepresentation(): void
    {
        $accessTokenEntity = AccessTokenEntity::fromState($this->state);

        $this->assertNull($accessTokenEntity->toString());

        $stringRepresentation = (string) $accessTokenEntity;

        $this->assertIsString($accessTokenEntity->toString());

        $this->assertSame($stringRepresentation, $accessTokenEntity->toString());
    }
}
