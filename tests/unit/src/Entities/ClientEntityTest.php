<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Entities;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Codebooks\RegistrationTypeEnum;
use SimpleSAML\Module\oidc\Entities\ClientEntity;

/**
 * @covers \SimpleSAML\Module\oidc\Entities\ClientEntity
 */
class ClientEntityTest extends TestCase
{
    protected array $state = [];
    protected string $id = 'id';
    protected string $secret = 'secret';
    protected string $name = 'name';
    protected string $description = 'description';
    protected array $redirectUri = ['https://localhost/redirect'];
    protected array $scopes = [];
    protected bool $isEnabled = true;
    protected bool $isConfidential = false;
    protected ?string $authSource = 'auth_source';
    protected string $owner = 'user@test.com';
    protected array $postLogoutRedirectUri = [];
    protected ?string $backChannelLogoutUri = null;
    protected ?string $entityIdentifier = null;
    protected ?array $clientRegistrationTypes = null;
    protected ?array $federationJwks = null;
    protected ?array $jwks = null;
    protected ?string $jwksUri = null;
    protected ?string $signedJwksUri = null;
    protected RegistrationTypeEnum $registrationType = RegistrationTypeEnum::Manual;
    protected ?DateTimeImmutable $updatedAt = null;
    protected ?DateTimeImmutable $createdAt = null;
    protected ?DateTimeImmutable $expiresAt = null;
    protected bool $isFederated = false;
    protected bool $isGeneric = false;

    protected function setUp(): void
    {
        $this->state = [
            'id' => 'id',
            'secret' => 'secret',
            'name' => 'name',
            'description' => 'description',
            'auth_source' => 'auth_source',
            'redirect_uri' => json_encode(['https://localhost/redirect']),
            'scopes' => json_encode([]),
            'is_enabled' => true,
            'is_confidential' => false,
            'owner' => 'user@test.com',
            'post_logout_redirect_uri' => json_encode([]),
            'backchannel_logout_uri' => null,
            'registration_type' => RegistrationTypeEnum::Manual->value,
            'updated_at' => null,
            'created_at' => null,
            'expires_at' => null,
            'is_federated' => false,
            'is_generic' => false,
        ];
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function mock(): ClientEntity
    {
        return new ClientEntity(
            $this->id,
            $this->secret,
            $this->name,
            $this->description,
            $this->redirectUri,
            $this->scopes,
            $this->isEnabled,
            $this->isConfidential,
            $this->authSource,
            $this->owner,
            $this->postLogoutRedirectUri,
            $this->backChannelLogoutUri,
            $this->entityIdentifier,
            $this->clientRegistrationTypes,
            $this->federationJwks,
            $this->jwks,
            $this->jwksUri,
            $this->signedJwksUri,
            $this->registrationType,
            $this->updatedAt,
            $this->createdAt,
            $this->expiresAt,
            $this->isFederated,
            $this->isGeneric,
        );
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            ClientEntity::class,
            $this->mock(),
        );

        $this->assertInstanceOf(
            ClientEntity::class,
            new ClientEntity('id', 'secret', 'name', 'description', ['redirectUri'], [], true),
        );
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testCanGetProperties(): void
    {
        $clientEntity = $this->mock();

        $this->assertSame('id', $clientEntity->getIdentifier());
        $this->assertSame('secret', $clientEntity->getSecret());
        $this->assertSame('description', $clientEntity->getDescription());
        $this->assertSame('auth_source', $clientEntity->getAuthSourceId());
        $this->assertSame(['https://localhost/redirect'], $clientEntity->getRedirectUri());
        $this->assertSame([], $clientEntity->getScopes());
        $this->assertSame(true, $clientEntity->isEnabled());
        $this->assertSame(false, $clientEntity->isConfidential());
        $this->assertSame([], $clientEntity->getPostLogoutRedirectUri());
        $this->assertSame(null, $clientEntity->getBackChannelLogoutUri());

        $clientEntity->restoreSecret('new_secret');
        $this->assertSame($clientEntity->getSecret(), 'new_secret');
        $clientEntity->setPostLogoutRedirectUri(['https://localhost/post']);
        $this->assertSame(['https://localhost/post'], $clientEntity->getPostLogoutRedirectUri());
        $clientEntity->setBackChannelLogoutUri('https://localhost/back');
        $this->assertSame('https://localhost/back', $clientEntity->getBackChannelLogoutUri());
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testCanChangeSecret(): void
    {
        $clientEntity = $this->mock();
        $this->assertSame('secret', $clientEntity->getSecret());
        $clientEntity->restoreSecret('new_secret');
        $this->assertSame($clientEntity->getSecret(), 'new_secret');
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
                'secret' => 'secret',
                'name' => 'name',
                'description' => 'description',
                'auth_source' => 'auth_source',
                'redirect_uri' => json_encode(['https://localhost/redirect']),
                'scopes' => json_encode([]),
                'is_enabled' => $this->state['is_enabled'],
                'is_confidential' => $this->state['is_confidential'],
                'owner' => 'user@test.com',
                'post_logout_redirect_uri' => json_encode([]),
                'backchannel_logout_uri' => null,
                'entity_identifier' => null,
                'client_registration_types' => null,
                'federation_jwks' => null,
                'jwks' => null,
                'jwks_uri' => null,
                'signed_jwks_uri' => null,
                'registration_type' => RegistrationTypeEnum::Manual->value,
                'updated_at' => null,
                'created_at' => null,
                'expires_at' => null,
                'is_federated' => $this->state['is_federated'],
                'is_generic' => $this->state['is_generic'],
                'extra_metadata' => null,
            ],
        );
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testCanExportAsArray(): void
    {
        $this->assertSame(
            $this->mock()->toArray(),
            [
                'id' => 'id',
                'secret' => 'secret',
                'name' => 'name',
                'description' => 'description',
                'auth_source' => 'auth_source',
                'redirect_uri' => ['https://localhost/redirect'],
                'scopes' => [],
                'is_enabled' => true,
                'is_confidential' => false,
                'owner' => 'user@test.com',
                'post_logout_redirect_uri' => [],
                'backchannel_logout_uri' => null,
                'entity_identifier' => null,
                'client_registration_types' => null,
                'federation_jwks' => null,
                'jwks' => null,
                'jwks_uri' => null,
                'signed_jwks_uri' => null,
                'registration_type' => RegistrationTypeEnum::Manual,
                'updated_at' => null,
                'created_at' => null,
                'expires_at' => null,
                'is_federated' => false,
                'is_generic' => false,
                'id_token_signed_response_alg' => null,
            ],
        );
    }
}
