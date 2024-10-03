<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Entities;

use DateTimeImmutable;
use DateTimeZone;
use Lcobucci\JWT\UnencryptedToken;
use League\OAuth2\Server\CryptKey;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\JsonWebTokenBuilderService;

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

    protected ClientEntity $clientEntityStub;

    protected ScopeEntity $scopeEntityOpenId;

    /**
     * @var \SimpleSAML\Module\oidc\Entities\ScopeEntity
     */
    protected ScopeEntity $scopeEntityProfile;
    protected CryptKey $privateKey;
    protected MockObject $jsonWebTokenBuilderServiceMock;
    protected MockObject $unencryptedTokenMock;
    protected DateTimeImmutable $expiryDateTime;
//    protected Stub $jwtConfigurationStub;

    /**
     * @throws \Exception
     * @throws \JsonException
     */
    protected function setUp(): void
    {
        $this->clientEntityStub = $this->createStub(ClientEntity::class);
        $this->clientEntityStub->method('getIdentifier')->willReturn($this->clientId);

        $this->scopeEntityOpenId = $this->createStub(ScopeEntity::class);
        $this->scopeEntityOpenId->method('getIdentifier')->willReturn('openid');
        $this->scopeEntityOpenId->method('jsonSerialize')->willReturn('openid');
        $this->scopeEntityProfile = $this->createStub(ScopeEntity::class);
        $this->scopeEntityProfile->method('getIdentifier')->willReturn('profile');
        $this->scopeEntityProfile->method('jsonSerialize')->willReturn('profile');

        $this->scopes = [
            $this->scopeEntityOpenId->getIdentifier() => $this->scopeEntityOpenId,
            $this->scopeEntityProfile->getIdentifier() => $this->scopeEntityProfile,
        ];

        $this->expiryDateTime = (new DateTimeImmutable('now', new DateTimeZone('UTC')))
            ->add(new \DateInterval('PT1M'));

        $this->jsonWebTokenBuilderServiceMock = $this->createMock(JsonWebTokenBuilderService::class);
        $this->unencryptedTokenMock = $this->createMock(UnencryptedToken::class);
        $this->jsonWebTokenBuilderServiceMock->method('getSignedProtocolJwt')
            ->willReturn($this->unencryptedTokenMock);

        //$this->jwtConfigurationStub = $this->createStub(\Lcobucci\JWT\Configuration::class); // Final class :(
        $certFolder = dirname(__DIR__, 4) . '/docker/ssp/';
        $privateKeyPath = $certFolder . ModuleConfig::DEFAULT_PKI_PRIVATE_KEY_FILENAME;
        $this->privateKey = new CryptKey($privateKeyPath);
    }

    public function mock(): AccessTokenEntity
    {
        return new AccessTokenEntity(
            $this->id,
            $this->clientEntityStub,
            $this->scopes,
            $this->expiryDateTime,
            $this->privateKey,
            $this->jsonWebTokenBuilderServiceMock,
            $this->userId,
            $this->authCodeId,
            $this->requestedClaims,
            $this->isRevoked,
            //            $this->jwtConfigurationStub,
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
        $this->unencryptedTokenMock->method('toString')->willReturn('token');
        $instance = $this->mock();
        $this->assertNull($instance->toString());

        $stringRepresentation = (string) $instance;

        $this->assertIsString($instance->toString());

        $this->assertSame($stringRepresentation, $instance->toString());
    }
}
