<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Entities;

use Closure;
use DateTimeImmutable;
use DateTimeZone;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Codebooks\RegistrationTypeEnum;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\OpenID\Codebooks\ClientRegistrationTypesEnum;
use SimpleSAML\OpenID\Codebooks\ResponseModesEnum;

/**
 * @covers \SimpleSAML\Module\oidc\Entities\ClientEntity
 */
#[AllowMockObjectsWithoutExpectations]
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
                'is_generic' => $this->state['is_generic'],
                'extra_metadata' => null,
                'registration_access_token' => null,
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
                'is_generic' => false,
                'id_token_signed_response_alg' => null,
                'allowed_response_modes' => [
                    'query',
                    'fragment',
                    'form_post',
                ],
                'require_pushed_authorization_requests' => false,
                'require_signed_request_object' => false,
                'request_uris' => [],
                'grant_types' => [],
                'response_types' => [],
                'token_endpoint_auth_method' => null,
                'default_max_age' => null,
                'require_auth_time' => false,
                'default_acr_values' => [],
                'initiate_login_uri' => null,
                'software_id' => null,
                'software_version' => null,
                'logo_uri' => null,
                'client_uri' => null,
                'policy_uri' => null,
                'tos_uri' => null,
                'application_type' => null,
                'contacts' => [],
                'authproc' => [],
                'add_claims_to_id_token' => false,
                'registration_access_token' => null,
            ],
        );
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testCanGetAuthProcFilters(): void
    {
        // No extra metadata -> empty list.
        $this->assertSame([], $this->mock()->getAuthProcFilters());

        $authProcFilters = [
            60 => ['class' => 'core:AttributeAdd', 'groups' => ['members']],
        ];

        $clientEntity = new ClientEntity(
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
            $this->isGeneric,
            [ClientEntity::KEY_AUTH_PROC_FILTERS => $authProcFilters],
        );

        $this->assertSame($authProcFilters, $clientEntity->getAuthProcFilters());
        $this->assertSame($authProcFilters, $clientEntity->toArray()[ClientEntity::KEY_AUTH_PROC_FILTERS]);
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testCanGetAddClaimsToIdToken(): void
    {
        // No extra metadata -> disabled by default.
        $this->assertFalse($this->mock()->getAddClaimsToIdToken());

        $clientEntity = new ClientEntity(
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
            $this->isGeneric,
            [ClientEntity::KEY_ADD_CLAIMS_TO_ID_TOKEN => true],
        );

        $this->assertTrue($clientEntity->getAddClaimsToIdToken());
        $this->assertTrue($clientEntity->toArray()[ClientEntity::KEY_ADD_CLAIMS_TO_ID_TOKEN]);
    }


    public function testEnforcementGettersReturnRawRegisteredValues(): void
    {
        // v7 transition: when not registered, these getters return the raw "unset" value (empty / null) rather
        // than synthesizing the OIDC DCR spec defaults, so the stored value stays the single source of truth and
        // pre-DCR clients are not retroactively constrained.
        $unset = $this->mock();
        $this->assertSame([], $unset->getGrantTypes());
        $this->assertSame([], $unset->getResponseTypes());
        $this->assertNull($unset->getTokenEndpointAuthMethod());

        // When registered, the stored values are returned.
        $registered = new ClientEntity(
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
            $this->isGeneric,
            [
                'grant_types' => ['authorization_code', 'refresh_token'],
                'response_types' => ['code'],
                'token_endpoint_auth_method' => 'private_key_jwt',
            ],
        );
        $this->assertSame(['authorization_code', 'refresh_token'], $registered->getGrantTypes());
        $this->assertSame(['code'], $registered->getResponseTypes());
        $this->assertSame('private_key_jwt', $registered->getTokenEndpointAuthMethod());
    }


    /**
     * The fixture with the optional fields it leaves unset, given by name.
     *
     * @param ?string[] $clientRegistrationTypes
     * @param ?array[] $federationJwks
     * @param ?array[] $jwks
     * @param ?array<string,mixed> $extraMetadata
     */
    protected function entityWith(
        ?string $entityIdentifier = null,
        ?array $clientRegistrationTypes = null,
        ?array $federationJwks = null,
        ?array $jwks = null,
        ?string $jwksUri = null,
        ?string $signedJwksUri = null,
        ?DateTimeImmutable $updatedAt = null,
        ?DateTimeImmutable $createdAt = null,
        ?DateTimeImmutable $expiresAt = null,
        ?array $extraMetadata = null,
        ?string $registrationAccessToken = null,
    ): ClientEntity {
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
            $entityIdentifier,
            $clientRegistrationTypes,
            $federationJwks,
            $jwks,
            $jwksUri,
            $signedJwksUri,
            $this->registrationType,
            $updatedAt,
            $createdAt,
            $expiresAt,
            $this->isGeneric,
            $extraMetadata,
            $registrationAccessToken,
        );
    }


    public function testRefusesAnEmptyIdentifier(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Client identifier cannot be empty.');

        new ClientEntity('', $this->secret, $this->name, $this->description, $this->redirectUri, [], true);
    }


    /**
     * League's trait lets a client hold one redirect URI as a string; the constructor takes a list, so
     * that form does not arise here and the list comes back as registered.
     */
    public function testRedirectUrisIsTheRegisteredList(): void
    {
        $this->assertSame(['https://localhost/redirect'], $this->mock()->getRedirectUris());
    }


    /**
     * @return array<string, array{0: ?string[], 1: string[], 2: ?string}>
     */
    public static function clientRegistrationTypesProvider(): array
    {
        return [
            'not set' => [null, [ClientRegistrationTypesEnum::Automatic->value], null],
            'set to none' => [[], [ClientRegistrationTypesEnum::Automatic->value], '["automatic"]'],
            'explicit' => [
                [ClientRegistrationTypesEnum::Explicit->value],
                [ClientRegistrationTypesEnum::Explicit->value],
                '["explicit"]',
            ],
        ];
    }


    /**
     * The registration types are required of a federation client, so a client with none falls back to
     * automatic. The state row keeps the distinction between unset and set to none only as far as null
     * against the fallback: an empty list is stored as automatic, since the row holds the getter's answer.
     *
     * @param ?string[] $clientRegistrationTypes
     * @param string[] $expected
     * @throws \JsonException
     */
    #[DataProvider('clientRegistrationTypesProvider')]
    public function testClientRegistrationTypesAreAsRegisteredOrAutomatic(
        ?array $clientRegistrationTypes,
        array $expected,
        ?string $expectedState,
    ): void {
        $entity = $this->entityWith(clientRegistrationTypes: $clientRegistrationTypes);

        $this->assertSame($expected, $entity->getClientRegistrationTypes());
        $this->assertSame($expectedState, $entity->getState()[ClientEntity::KEY_CLIENT_REGISTRATION_TYPES]);
        $this->assertSame(
            $clientRegistrationTypes,
            $entity->toArray()[ClientEntity::KEY_CLIENT_REGISTRATION_TYPES],
        );
    }


    /**
     * The optional fields the fixture leaves unset, read back: the arrays and strings as given, the
     * moments as the instances given.
     */
    public function testCarriesTheOptionalFieldsAsGiven(): void
    {
        $federationJwks = ['keys' => [['kty' => 'RSA', 'kid' => 'fed-1']]];
        $jwks = ['keys' => [['kty' => 'EC', 'kid' => 'rp-1']]];
        $updatedAt = new DateTimeImmutable('2026-09-19 10:15:00', new DateTimeZone('UTC'));
        $createdAt = new DateTimeImmutable('2026-09-18 09:00:00', new DateTimeZone('UTC'));
        $expiresAt = new DateTimeImmutable('2027-09-18 09:00:00', new DateTimeZone('Europe/Zagreb'));

        $entity = $this->entityWith(
            entityIdentifier: 'https://rp.example.org',
            federationJwks: $federationJwks,
            jwks: $jwks,
            jwksUri: 'https://rp.example.org/jwks',
            signedJwksUri: 'https://rp.example.org/signed-jwks',
            updatedAt: $updatedAt,
            createdAt: $createdAt,
            expiresAt: $expiresAt,
        );

        $this->assertSame('https://rp.example.org', $entity->getEntityIdentifier());
        $this->assertSame($federationJwks, $entity->getFederationJwks());
        $this->assertSame($jwks, $entity->getJwks());
        $this->assertSame('https://rp.example.org/jwks', $entity->getJwksUri());
        $this->assertSame('https://rp.example.org/signed-jwks', $entity->getSignedJwksUri());
        $this->assertSame($updatedAt, $entity->getUpdatedAt());
        $this->assertSame($createdAt, $entity->getCreatedAt());
        $this->assertSame($expiresAt, $entity->getExpiresAt());
    }


    /**
     * The state row with the optional fields the fixture leaves unset filled in: the key material, the
     * lists and the extra metadata as JSON, the moments as 'Y-m-d H:i:s' in the zone they hold, the token
     * hash as is.
     *
     * @throws \JsonException
     */
    public function testStateCarriesTheOptionalFields(): void
    {
        $this->backChannelLogoutUri = 'https://rp.example.org/backchannel-logout';

        $entity = $this->entityWith(
            entityIdentifier: 'https://rp.example.org',
            clientRegistrationTypes: [ClientRegistrationTypesEnum::Explicit->value],
            federationJwks: ['keys' => [['kty' => 'RSA', 'kid' => 'fed-1']]],
            jwks: ['keys' => [['kty' => 'EC', 'kid' => 'rp-1']]],
            jwksUri: 'https://rp.example.org/jwks',
            signedJwksUri: 'https://rp.example.org/signed-jwks',
            updatedAt: new DateTimeImmutable('2026-09-19 10:15:00', new DateTimeZone('UTC')),
            createdAt: new DateTimeImmutable('2026-09-18 09:00:00', new DateTimeZone('UTC')),
            expiresAt: new DateTimeImmutable('2027-09-18 09:00:00', new DateTimeZone('Europe/Zagreb')),
            extraMetadata: ['id_token_signed_response_alg' => 'RS256', 'contacts' => ['admin@rp.example.org']],
            registrationAccessToken: 'hash-of-the-registration-access-token',
        );

        $this->assertSame(
            [
                'id' => 'id',
                'secret' => 'secret',
                'name' => 'name',
                'description' => 'description',
                'auth_source' => 'auth_source',
                'redirect_uri' => '["https:\/\/localhost\/redirect"]',
                'scopes' => '[]',
                'is_enabled' => true,
                'is_confidential' => false,
                'owner' => 'user@test.com',
                'post_logout_redirect_uri' => '[]',
                'backchannel_logout_uri' => 'https://rp.example.org/backchannel-logout',
                'entity_identifier' => 'https://rp.example.org',
                'client_registration_types' => '["explicit"]',
                'federation_jwks' => '{"keys":[{"kty":"RSA","kid":"fed-1"}]}',
                'jwks' => '{"keys":[{"kty":"EC","kid":"rp-1"}]}',
                'jwks_uri' => 'https://rp.example.org/jwks',
                'signed_jwks_uri' => 'https://rp.example.org/signed-jwks',
                'registration_type' => 'manual',
                'updated_at' => '2026-09-19 10:15:00',
                'created_at' => '2026-09-18 09:00:00',
                'expires_at' => '2027-09-18 09:00:00',
                'is_generic' => false,
                'extra_metadata' => '{"id_token_signed_response_alg":"RS256","contacts":["admin@rp.example.org"]}',
                'registration_access_token' => 'hash-of-the-registration-access-token',
            ],
            $entity->getState(),
        );
    }


    /**
     * @return array<string, array{0: ?\DateTimeImmutable, 1: bool}>
     */
    public static function expiryProvider(): array
    {
        return [
            'no expiry' => [null, false],
            'a day ago' => [new DateTimeImmutable('-1 day'), true],
            'a day from now' => [new DateTimeImmutable('+1 day'), false],
        ];
    }


    /**
     * A client with no expiry never expires; one with an expiry has once that moment is behind the clock.
     */
    #[DataProvider('expiryProvider')]
    public function testIsExpiredOnceTheExpiryIsBehindTheClock(?DateTimeImmutable $expiresAt, bool $expected): void
    {
        $this->assertSame($expected, $this->entityWith(expiresAt: $expiresAt)->isExpired());
    }


    public function testExtraMetadataIsAsGivenOrEmpty(): void
    {
        $this->assertSame([], $this->mock()->getExtraMetadata());
        $this->assertSame(
            ['software_id' => 'rp-suite'],
            $this->entityWith(extraMetadata: ['software_id' => 'rp-suite'])->getExtraMetadata(),
        );
    }


    /**
     * The hash is what the client configuration endpoint checks a presented token against; it is carried
     * in the row and the export, and replaced when the token is rotated.
     *
     * @throws \JsonException
     */
    public function testCarriesTheRegistrationAccessTokenHash(): void
    {
        $this->assertNull($this->mock()->getRegistrationAccessTokenHash());

        $entity = $this->entityWith(registrationAccessToken: 'hash-1');
        $this->assertHashIs('hash-1', $entity);

        $entity->setRegistrationAccessTokenHash('hash-2');
        $this->assertHashIs('hash-2', $entity);

        $entity->setRegistrationAccessTokenHash(null);
        $this->assertHashIs(null, $entity);
    }


    /**
     * The hash as the getter, the state row and the export answer it.
     *
     * @throws \JsonException
     */
    protected function assertHashIs(?string $expected, ClientEntity $entity): void
    {
        $this->assertSame($expected, $entity->getRegistrationAccessTokenHash());
        $this->assertSame($expected, $entity->getState()[ClientEntity::KEY_REGISTRATION_ACCESS_TOKEN]);
        $this->assertSame($expected, $entity->toArray()[ClientEntity::KEY_REGISTRATION_ACCESS_TOKEN]);
    }


    /**
     * @return array<string, array{0: ?array<string,mixed>, 1: ?string}>
     */
    public static function idTokenSignedResponseAlgProvider(): array
    {
        return [
            'no extra metadata' => [null, null],
            'not registered' => [[], null],
            'not a string' => [['id_token_signed_response_alg' => ['RS256']], null],
            'registered' => [['id_token_signed_response_alg' => 'RS256'], 'RS256'],
        ];
    }


    /**
     * @param ?array<string,mixed> $extraMetadata
     */
    #[DataProvider('idTokenSignedResponseAlgProvider')]
    public function testIdTokenSignedResponseAlgIsTheRegisteredString(
        ?array $extraMetadata,
        ?string $expected,
    ): void {
        $this->assertSame($expected, $this->entityWith(extraMetadata: $extraMetadata)->getIdTokenSignedResponseAlg());
    }


    /**
     * @return array<string, array{0: ?array<string,mixed>, 1: string[]}>
     */
    public static function allowedResponseModesProvider(): array
    {
        $allThree = [
            ResponseModesEnum::Query->value,
            ResponseModesEnum::Fragment->value,
            ResponseModesEnum::FormPost->value,
        ];

        return [
            'no extra metadata' => [null, $allThree],
            'not registered' => [[], $allThree],
            'not a list' => [['allowed_response_modes' => ResponseModesEnum::Query->value], $allThree],
            'one registered' => [
                ['allowed_response_modes' => [ResponseModesEnum::Query->value]],
                [ResponseModesEnum::Query->value],
            ],
            'none registered' => [['allowed_response_modes' => []], []],
        ];
    }


    /**
     * A client with no list registered may use all three response modes; a list, an empty one included,
     * is what it registered and all it may use.
     *
     * @param ?array<string,mixed> $extraMetadata
     * @param string[] $expected
     */
    #[DataProvider('allowedResponseModesProvider')]
    public function testAllowedResponseModesAreTheRegisteredOnesOrAllThree(
        ?array $extraMetadata,
        array $expected,
    ): void {
        $this->assertSame($expected, $this->entityWith(extraMetadata: $extraMetadata)->getAllowedResponseModes());
    }


    /**
     * The five list-of-strings getters, each under every shape the registered value can take.
     *
     * @return array<string, array{0: \Closure, 1: ?array<string,mixed>, 2: string[]}>
     */
    public static function stringListProvider(): array
    {
        $getters = [
            'request_uris' => fn(ClientEntity $entity): array => $entity->getRequestUris(),
            'grant_types' => fn(ClientEntity $entity): array => $entity->getGrantTypes(),
            'response_types' => fn(ClientEntity $entity): array => $entity->getResponseTypes(),
            'default_acr_values' => fn(ClientEntity $entity): array => $entity->getDefaultAcrValues(),
            'contacts' => fn(ClientEntity $entity): array => $entity->getContacts(),
        ];

        $cases = [];
        foreach ($getters as $key => $getter) {
            $cases["$key, no extra metadata"] = [$getter, null, []];
            $cases["$key, not registered"] = [$getter, [], []];
            $cases["$key, not a list"] = [$getter, [$key => 'first'], []];
            $cases["$key, a list with other types in it"] = [
                $getter,
                [$key => ['first', 42, null, 'second']],
                ['first', 'second'],
            ];
            $cases["$key, a list not indexed from zero"] = [
                $getter,
                [$key => [3 => 'first', 7 => 'second']],
                ['first', 'second'],
            ];
        }

        return $cases;
    }


    /**
     * Only the strings of a registered list count, re-indexed from zero, and anything but a list is none.
     *
     * @param ?array<string,mixed> $extraMetadata
     * @param string[] $expected
     */
    #[DataProvider('stringListProvider')]
    public function testListGettersKeepOnlyTheStrings(Closure $getter, ?array $extraMetadata, array $expected): void
    {
        $this->assertSame($expected, $getter($this->entityWith(extraMetadata: $extraMetadata)));
    }


    /**
     * @return array<string, array{0: ?array<string,mixed>, 1: ?int}>
     */
    public static function defaultMaxAgeProvider(): array
    {
        return [
            'no extra metadata' => [null, null],
            'not registered' => [[], null],
            'an integer' => [['default_max_age' => 3600], 3600],
            'zero' => [['default_max_age' => 0], 0],
            'an integer as a string' => [['default_max_age' => '600'], 600],
            'negative' => [['default_max_age' => -1], null],
            'a float' => [['default_max_age' => 3600.0], null],
            'a float as a string' => [['default_max_age' => '3600.0'], null],
            'not a number' => [['default_max_age' => 'soon'], null],
            'a boolean' => [['default_max_age' => true], null],
        ];
    }


    /**
     * A default max_age is a number of seconds, so a non-negative integer, given as one or as a string of
     * one; anything else is no default.
     *
     * @param ?array<string,mixed> $extraMetadata
     */
    #[DataProvider('defaultMaxAgeProvider')]
    public function testDefaultMaxAgeIsANonNegativeInteger(?array $extraMetadata, ?int $expected): void
    {
        $this->assertSame($expected, $this->entityWith(extraMetadata: $extraMetadata)->getDefaultMaxAge());
    }
}
