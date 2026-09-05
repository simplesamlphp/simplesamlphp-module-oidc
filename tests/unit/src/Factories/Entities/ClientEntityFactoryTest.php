<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Factories\Entities;

use DateTimeImmutable;
use JsonException;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Bridges\SspBridge\Utils;
use SimpleSAML\Module\oidc\Codebooks\RegistrationTypeEnum;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Factories\Entities\ClientEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\ClientRegistrationTypesEnum;
use SimpleSAML\OpenID\Codebooks\ErrorsEnum;
use SimpleSAML\OpenID\Codebooks\GrantTypesEnum;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairBag;
use SimpleSAML\Utils\Random;
use ValueError;

#[CoversClass(ClientEntityFactory::class)]
#[UsesClass(ClientEntity::class)]
#[AllowMockObjectsWithoutExpectations]
class ClientEntityFactoryTest extends TestCase
{
    protected MockObject $sspBridgeMock;

    protected MockObject $moduleConfigMock;

    /** Backing value for ModuleConfig::getDcrRegisteredClientsEnabled() in tests (real default is true). */
    protected bool $dcrRegisteredClientsEnabled = true;

    protected Helpers $helpers;


    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->helpers = new Helpers();

        $randomMock = $this->createMock(Random::class);
        $randomMock->method('generateID')->willReturn('generated123');
        $utilsMock = $this->createMock(Utils::class);
        $utilsMock->method('random')->willReturn($randomMock);
        $this->sspBridgeMock = $this->createMock(SspBridge::class);
        $this->sspBridgeMock->method('utils')->willReturn($utilsMock);

        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getScopes')->willReturn([
            'openid' => ['description' => 'openid'],
            'profile' => ['description' => 'profile'],
            'email' => ['description' => 'email'],
            'offline_access' => ['description' => 'offline_access'],
        ]);
        // Real default is true (auto-enable); individual tests may flip $this->dcrRegisteredClientsEnabled.
        $this->moduleConfigMock->method('getDcrRegisteredClientsEnabled')
            ->willReturnCallback(fn(): bool => $this->dcrRegisteredClientsEnabled);

        $signatureKeyPairBagMock = $this->createMock(SignatureKeyPairBag::class);
        $signatureKeyPairBagMock->method('getAllAlgorithmNamesUnique')->willReturn(['RS256', 'ES256']);
        $this->moduleConfigMock->method('getProtocolSignatureKeyPairBag')->willReturn($signatureKeyPairBagMock);
    }


    protected function sut(): ClientEntityFactory
    {
        return new ClientEntityFactory(
            $this->sspBridgeMock,
            $this->helpers,
            $this->moduleConfigMock,
        );
    }


    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(ClientEntityFactory::class, $this->sut());
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromRegistrationDataAcceptsSupportedIdTokenSignedResponseAlg(): void
    {
        $client = $this->sut()->fromRegistrationData(
            [
                ClaimsEnum::RedirectUris->value => ['https://example.org/cb'],
                ClaimsEnum::IdTokenSignedResponseAlg->value => 'ES256',
            ],
            RegistrationTypeEnum::FederatedAutomatic,
        );

        $this->assertSame('ES256', $client->getIdTokenSignedResponseAlg());
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromRegistrationDataRejectsUnsupportedIdTokenSignedResponseAlg(): void
    {
        try {
            $this->sut()->fromRegistrationData(
                [
                    ClaimsEnum::RedirectUris->value => ['https://example.org/cb'],
                    ClaimsEnum::IdTokenSignedResponseAlg->value => 'HS256',
                ],
                RegistrationTypeEnum::FederatedAutomatic,
            );
            $this->fail('Expected ' . OidcServerException::class . ' was not thrown.');
        } catch (OidcServerException $exception) {
            // Error code mandated by the Dynamic Client Registration spec (RFC 7591, section 3.2.2).
            $this->assertSame(ErrorsEnum::InvalidClientMetadata->value, $exception->getPayload()['error']);
            $this->assertStringContainsString('HS256', $exception->getPayload()['error_description']);
        }
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromRegistrationDataWithoutIdTokenSignedResponseAlg(): void
    {
        $client = $this->sut()->fromRegistrationData(
            [ClaimsEnum::RedirectUris->value => ['https://example.org/cb']],
            RegistrationTypeEnum::FederatedAutomatic,
        );

        $this->assertNull($client->getIdTokenSignedResponseAlg());
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromRegistrationDataThrowsWhenRedirectUrisMissing(): void
    {
        $this->expectException(OidcServerException::class);

        $this->sut()->fromRegistrationData([], RegistrationTypeEnum::FederatedAutomatic);
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromRegistrationDataSetsDynamicRegistrationType(): void
    {
        $client = $this->sut()->fromRegistrationData(
            [ClaimsEnum::RedirectUris->value => ['https://example.org/cb']],
            RegistrationTypeEnum::Dynamic,
        );

        $this->assertSame(RegistrationTypeEnum::Dynamic, $client->getRegistrationType());
        // Newly registered clients carry no Registration Access Token hash until the controller assigns one.
        $this->assertNull($client->getRegistrationAccessTokenHash());
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromRegistrationDataStoresAndEchoesInformationalMetadata(): void
    {
        $client = $this->sut()->fromRegistrationData(
            [
                ClaimsEnum::RedirectUris->value => ['https://example.org/cb'],
                ClaimsEnum::LogoUri->value => 'https://example.org/logo.png',
                ClaimsEnum::Contacts->value => ['admin@example.org'],
                ClaimsEnum::ApplicationType->value => 'web',
            ],
            RegistrationTypeEnum::Dynamic,
        );

        $extraMetadata = $client->getExtraMetadata();
        $this->assertSame('https://example.org/logo.png', $extraMetadata[ClaimsEnum::LogoUri->value]);
        $this->assertSame(['admin@example.org'], $extraMetadata[ClaimsEnum::Contacts->value]);
        $this->assertSame('web', $extraMetadata[ClaimsEnum::ApplicationType->value]);
    }


    /**
     * Admin-only client properties (e.g. authproc filters) must NEVER be honored
     * when supplied through client registration metadata, since an authproc
     * filter names a PHP class executed server-side (remote code execution
     * vector). They can only be set by an administrator via the admin UI / API.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromRegistrationDataIgnoresAdminOnlyAuthProcFilters(): void
    {
        $client = $this->sut()->fromRegistrationData(
            [
                ClaimsEnum::RedirectUris->value => ['https://example.org/cb'],
                // Malicious client tries to inject an authproc filter.
                ClientEntity::KEY_AUTH_PROC_FILTERS => [
                    60 => ['class' => 'core:PHP', 'code' => 'system("id");'],
                ],
            ],
            RegistrationTypeEnum::FederatedAutomatic,
        );

        $this->assertSame([], $client->getAuthProcFilters());
    }


    /**
     * An administrator-set authproc filter on an existing client must be
     * preserved across re-registration, and must not be overridable by the
     * (untrusted) registration metadata.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromRegistrationDataPreservesAdminSetAuthProcFiltersAndIgnoresSuppliedOnes(): void
    {
        $adminSetFilters = [
            50 => ['class' => 'core:AttributeAdd', 'groups' => ['members']],
        ];

        $existingClient = $this->createMock(ClientEntity::class);
        $existingClient->method('getExtraMetadata')->willReturn(
            [ClientEntity::KEY_AUTH_PROC_FILTERS => $adminSetFilters],
        );

        $client = $this->sut()->fromRegistrationData(
            [
                ClaimsEnum::RedirectUris->value => ['https://example.org/cb'],
                // Attempt to overwrite the admin-set filters via registration metadata.
                ClientEntity::KEY_AUTH_PROC_FILTERS => [
                    99 => ['class' => 'core:PHP', 'code' => 'system("id");'],
                ],
            ],
            RegistrationTypeEnum::FederatedAutomatic,
            existingClient: $existingClient,
        );

        $this->assertSame($adminSetFilters, $client->getAuthProcFilters());
    }


    /**
     * The administrator-only "release user claims in ID Token" property must NEVER be honored when supplied
     * through client registration metadata; an untrusted client must not be able to force its own claims into
     * the ID Token. It can only be set by an administrator via the admin UI / API.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromRegistrationDataIgnoresAdminOnlyAddClaimsToIdToken(): void
    {
        $client = $this->sut()->fromRegistrationData(
            [
                ClaimsEnum::RedirectUris->value => ['https://example.org/cb'],
                // Client tries to opt itself into ID Token claim release.
                ClientEntity::KEY_ADD_CLAIMS_TO_ID_TOKEN => true,
            ],
            RegistrationTypeEnum::FederatedAutomatic,
        );

        $this->assertFalse($client->getAddClaimsToIdToken());
    }


    /**
     * An administrator-set "release user claims in ID Token" value on an existing client must be preserved
     * across re-registration, and must not be overridable by the (untrusted) registration metadata.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromRegistrationDataPreservesAdminSetAddClaimsToIdTokenAndIgnoresSuppliedOnes(): void
    {
        $existingClient = $this->createMock(ClientEntity::class);
        $existingClient->method('getExtraMetadata')->willReturn(
            [ClientEntity::KEY_ADD_CLAIMS_TO_ID_TOKEN => true],
        );

        $client = $this->sut()->fromRegistrationData(
            [
                ClaimsEnum::RedirectUris->value => ['https://example.org/cb'],
                // Attempt to turn the admin-set value off via registration metadata.
                ClientEntity::KEY_ADD_CLAIMS_TO_ID_TOKEN => false,
            ],
            RegistrationTypeEnum::FederatedAutomatic,
            existingClient: $existingClient,
        );

        $this->assertTrue($client->getAddClaimsToIdToken());
    }


    /**
     * The behavioral default metadata (default_max_age, require_auth_time, default_acr_values) and informational
     * metadata (initiate_login_uri, software_id, software_version) are persisted from a registration request.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromRegistrationDataPersistsAdditionalMetadata(): void
    {
        $client = $this->sut()->fromRegistrationData(
            [
                ClaimsEnum::RedirectUris->value => ['https://example.org/cb'],
                ClaimsEnum::DefaultMaxAge->value => 600,
                ClaimsEnum::RequireAuthTime->value => true,
                ClaimsEnum::DefaultAcrValues->value => ['acr-1', 'acr-2'],
                ClaimsEnum::InitiateLoginUri->value => 'https://example.org/initiate',
                ClaimsEnum::SoftwareId->value => 'suite',
                ClaimsEnum::SoftwareVersion->value => '2.0',
            ],
            RegistrationTypeEnum::Dynamic,
        );

        $this->assertSame(600, $client->getDefaultMaxAge());
        $this->assertTrue($client->getRequireAuthTime());
        $this->assertSame(['acr-1', 'acr-2'], $client->getDefaultAcrValues());
        $this->assertSame('https://example.org/initiate', $client->getInitiateLoginUri());
        $this->assertSame('suite', $client->getSoftwareId());
        $this->assertSame('2.0', $client->getSoftwareVersion());
    }


    /**
     * request_uris from a registration request are persisted (into extra metadata) so they can be
     * exact-matched when a Request Object is later passed by reference (request_uri). The fragment, which OIDC
     * Core allows as a content hash, is preserved.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromRegistrationDataPersistsRequestUris(): void
    {
        $client = $this->sut()->fromRegistrationData(
            [
                ClaimsEnum::RedirectUris->value => ['https://example.org/cb'],
                ClaimsEnum::RequestUris->value => ['https://example.org/request-object#aHash'],
            ],
            RegistrationTypeEnum::Dynamic,
        );

        $this->assertSame(['https://example.org/request-object#aHash'], $client->getRequestUris());
    }


    /**
     * A Dynamic registration that omits grant_types / response_types / token_endpoint_auth_method gets the
     * OIDC DCR 1.0 defaults persisted, so they can be returned in the registration response and enforced.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromRegistrationDataAppliesDefaultGrantResponseAndAuthMethodForDynamic(): void
    {
        $client = $this->sut()->fromRegistrationData(
            [ClaimsEnum::RedirectUris->value => ['https://example.org/cb']],
            RegistrationTypeEnum::Dynamic,
        );

        $this->assertSame(['authorization_code'], $client->getGrantTypes());
        $this->assertSame(['code'], $client->getResponseTypes());
        $this->assertSame('client_secret_basic', $client->getTokenEndpointAuthMethod());
    }


    /**
     * Explicit grant_types / response_types / token_endpoint_auth_method on a Dynamic registration are persisted
     * as-is.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromRegistrationDataPersistsExplicitGrantResponseAndAuthMethod(): void
    {
        $client = $this->sut()->fromRegistrationData(
            [
                ClaimsEnum::RedirectUris->value => ['https://example.org/cb'],
                ClaimsEnum::GrantTypes->value => ['authorization_code', 'refresh_token'],
                ClaimsEnum::ResponseTypes->value => ['code'],
                ClaimsEnum::TokenEndpointAuthMethod->value => 'private_key_jwt',
            ],
            RegistrationTypeEnum::Dynamic,
        );

        $this->assertSame(['authorization_code', 'refresh_token'], $client->getGrantTypes());
        $this->assertSame(['code'], $client->getResponseTypes());
        $this->assertSame('private_key_jwt', $client->getTokenEndpointAuthMethod());
    }


    /**
     * The OIDC DCR response_type <-> grant_type correspondence is normalized: grant types required by the
     * registered response_types are added to grant_types, even when the client omitted grant_types (so it falls
     * back to the authorization_code default first).
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromRegistrationDataNormalizesGrantTypesToResponseTypeCorrespondence(): void
    {
        // Client declares implicit response types but omits grant_types -> implicit must be added (alongside the
        // authorization_code default).
        $client = $this->sut()->fromRegistrationData(
            [
                ClaimsEnum::RedirectUris->value => ['https://example.org/cb'],
                ClaimsEnum::ResponseTypes->value => ['code', 'id_token'],
            ],
            RegistrationTypeEnum::Dynamic,
        );

        $this->assertSame(['authorization_code', 'implicit'], $client->getGrantTypes());
        $this->assertSame(['code', 'id_token'], $client->getResponseTypes());
    }


    /**
     * The client type (confidential/public) follows token_endpoint_auth_method: `none` yields a public client.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromRegistrationDataDerivesPublicTypeFromNoneAuthMethod(): void
    {
        $client = $this->sut()->fromRegistrationData(
            [
                ClaimsEnum::RedirectUris->value => ['https://example.org/cb'],
                ClaimsEnum::TokenEndpointAuthMethod->value => 'none',
            ],
            RegistrationTypeEnum::Dynamic,
        );

        $this->assertFalse($client->isConfidential());
        $this->assertSame('none', $client->getTokenEndpointAuthMethod());
    }


    /**
     * application_type `native` (with no auth method provided) yields a public client.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromRegistrationDataDerivesPublicTypeFromNativeApplicationType(): void
    {
        $client = $this->sut()->fromRegistrationData(
            [
                ClaimsEnum::RedirectUris->value => ['https://example.org/cb'],
                ClaimsEnum::ApplicationType->value => 'native',
            ],
            RegistrationTypeEnum::Dynamic,
        );

        $this->assertFalse($client->isConfidential());
        $this->assertSame('none', $client->getTokenEndpointAuthMethod());
    }


    /**
     * The client type is re-derived on an RFC 7592 update too: changing token_endpoint_auth_method from `none` to a
     * real authentication method flips the client from public to confidential (previously it was carried over from
     * the existing client and never recomputed).
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromRegistrationDataReDerivesClientTypeOnUpdate(): void
    {
        $publicClient = $this->sut()->fromRegistrationData(
            [
                ClaimsEnum::RedirectUris->value => ['https://example.org/cb'],
                ClaimsEnum::TokenEndpointAuthMethod->value => 'none',
            ],
            RegistrationTypeEnum::Dynamic,
        );
        $this->assertFalse($publicClient->isConfidential());

        $updatedClient = $this->sut()->fromRegistrationData(
            [
                ClaimsEnum::RedirectUris->value => ['https://example.org/cb'],
                ClaimsEnum::TokenEndpointAuthMethod->value => 'client_secret_basic',
            ],
            RegistrationTypeEnum::Dynamic,
            existingClient: $publicClient,
        );

        $this->assertTrue($updatedClient->isConfidential());
        $this->assertSame('client_secret_basic', $updatedClient->getTokenEndpointAuthMethod());
    }


    /**
     * A new Dynamic client is created enabled by default (auto-enable).
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromRegistrationDataEnablesNewDynamicClientByDefault(): void
    {
        $this->dcrRegisteredClientsEnabled = true;

        $client = $this->sut()->fromRegistrationData(
            [ClaimsEnum::RedirectUris->value => ['https://example.org/cb']],
            RegistrationTypeEnum::Dynamic,
        );

        $this->assertTrue($client->isEnabled());
    }


    /**
     * When configured for review, a new Dynamic client is created disabled.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromRegistrationDataCreatesNewDynamicClientDisabledWhenConfigured(): void
    {
        $this->dcrRegisteredClientsEnabled = false;

        $client = $this->sut()->fromRegistrationData(
            [ClaimsEnum::RedirectUris->value => ['https://example.org/cb']],
            RegistrationTypeEnum::Dynamic,
        );

        $this->assertFalse($client->isEnabled());
    }


    /**
     * The review setting applies to Dynamic registrations only: OpenID Federation automatic registrations are
     * always created enabled (they are vouched for by their trust chain).
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromRegistrationDataAlwaysEnablesFederatedClientRegardlessOfReviewSetting(): void
    {
        $this->dcrRegisteredClientsEnabled = false;

        $client = $this->sut()->fromRegistrationData(
            [ClaimsEnum::RedirectUris->value => ['https://example.org/cb']],
            RegistrationTypeEnum::FederatedAutomatic,
        );

        $this->assertTrue($client->isEnabled());
    }


    /**
     * The review gate only applies to the initial registration: an update preserves the existing enabled state
     * (so re-registering an already-approved client does not silently disable it again).
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromRegistrationDataUpdatePreservesEnabledStateUnderReviewSetting(): void
    {
        $this->dcrRegisteredClientsEnabled = true;
        $existingClient = $this->sut()->fromRegistrationData(
            [ClaimsEnum::RedirectUris->value => ['https://example.org/cb']],
            RegistrationTypeEnum::Dynamic,
        );
        $this->assertTrue($existingClient->isEnabled());

        // Even if the option is now off, updating an existing (enabled) client keeps it enabled.
        $this->dcrRegisteredClientsEnabled = false;
        $updatedClient = $this->sut()->fromRegistrationData(
            [ClaimsEnum::RedirectUris->value => ['https://example.org/cb2']],
            RegistrationTypeEnum::Dynamic,
            existingClient: $existingClient,
        );

        $this->assertTrue($updatedClient->isEnabled());
    }


    /**
     * RFC 7592 update is a full replace: client-settable metadata omitted from the update request is reset to its
     * default (or removed), not retained from the previous registration.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromRegistrationDataUpdateReplacesOmittedClientMetadata(): void
    {
        $this->moduleConfigMock->method('getDcrDefaultScopes')->willReturn(['openid']);

        $original = $this->sut()->fromRegistrationData(
            [
                ClaimsEnum::RedirectUris->value => ['https://example.org/cb'],
                ClaimsEnum::ClientName->value => 'Original Name',
                ClaimsEnum::Scope->value => 'openid profile',
                ClaimsEnum::GrantTypes->value => ['authorization_code', 'refresh_token'],
                ClaimsEnum::LogoUri->value => 'https://example.org/logo.png',
                ClaimsEnum::PostLogoutRedirectUris->value => ['https://example.org/post'],
            ],
            RegistrationTypeEnum::Dynamic,
        );
        $this->assertSame('Original Name', $original->getName());
        $this->assertContains('refresh_token', $original->getGrantTypes());
        $this->assertSame('https://example.org/logo.png', $original->getLogoUri());

        // Update with redirect_uris only: every other client-settable field must be reset.
        $updated = $this->sut()->fromRegistrationData(
            [ClaimsEnum::RedirectUris->value => ['https://example.org/cb2']],
            RegistrationTypeEnum::Dynamic,
            existingClient: $original,
        );

        $this->assertSame(['https://example.org/cb2'], $updated->getRedirectUris());
        $this->assertSame($updated->getIdentifier(), $updated->getName()); // client_name reset to client_id
        $this->assertSame(['authorization_code'], $updated->getGrantTypes()); // reset to DCR default
        $this->assertSame(['openid'], $updated->getScopes()); // reset to default scope set
        $this->assertNull($updated->getLogoUri()); // removed
        $this->assertSame([], $updated->getPostLogoutRedirectUri()); // removed

        // Server-managed identity is preserved across the update.
        $this->assertSame($original->getIdentifier(), $updated->getIdentifier());
        $this->assertSame($original->getSecret(), $updated->getSecret());
    }


    /**
     * Admin-only metadata (e.g. authproc, which a registering client can never set) survives an RFC 7592 update,
     * even though the update otherwise replaces client-settable metadata.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromRegistrationDataUpdateRetainsAdminOnlyMetadata(): void
    {
        $authProcFilters = [60 => ['class' => 'core:AttributeAdd']];
        $existing = $this->sut()->fromData(
            'client-1',
            'secret-1',
            'Name',
            '',
            ['https://example.org/cb'],
            ['openid'],
            true,
            true,
            registrationType: RegistrationTypeEnum::Dynamic,
            extraMetadata: [ClientEntity::KEY_AUTH_PROC_FILTERS => $authProcFilters],
        );
        $this->assertSame($authProcFilters, $existing->getAuthProcFilters());

        $updated = $this->sut()->fromRegistrationData(
            [ClaimsEnum::RedirectUris->value => ['https://example.org/cb2']],
            RegistrationTypeEnum::Dynamic,
            existingClient: $existing,
        );

        $this->assertSame($authProcFilters, $updated->getAuthProcFilters());
    }


    /**
     * Federation automatic registrations are not forced to the Dynamic defaults: nothing is persisted for these
     * three fields unless the federation metadata provides them.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromRegistrationDataDoesNotForceGrantTypeDefaultsForFederated(): void
    {
        $client = $this->sut()->fromRegistrationData(
            [ClaimsEnum::RedirectUris->value => ['https://example.org/cb']],
            RegistrationTypeEnum::FederatedAutomatic,
        );

        $extraMetadata = $client->getExtraMetadata();
        $this->assertArrayNotHasKey(ClaimsEnum::GrantTypes->value, $extraMetadata);
        $this->assertArrayNotHasKey(ClaimsEnum::ResponseTypes->value, $extraMetadata);
        $this->assertArrayNotHasKey(ClaimsEnum::TokenEndpointAuthMethod->value, $extraMetadata);
    }


    /**
     * A Dynamic registration that omits `scope` is assigned the configured DCR default scope set.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromRegistrationDataAssignsDefaultScopesForScopelessDynamicRegistration(): void
    {
        $this->moduleConfigMock->method('getDcrDefaultScopes')
            ->willReturn(['openid', 'profile', 'email', 'offline_access']);

        $client = $this->sut()->fromRegistrationData(
            [ClaimsEnum::RedirectUris->value => ['https://example.org/cb']],
            RegistrationTypeEnum::Dynamic,
        );

        $this->assertEqualsCanonicalizing(
            ['openid', 'profile', 'email', 'offline_access'],
            array_values($client->getScopes()),
        );
    }


    /**
     * The DCR default scope set must NOT be applied to OpenID Federation automatic registrations; a federated
     * client that omits `scope` keeps the conservative `openid`-only default.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromRegistrationDataDoesNotApplyDcrDefaultScopesForFederatedRegistration(): void
    {
        $this->moduleConfigMock->expects($this->never())->method('getDcrDefaultScopes');

        $client = $this->sut()->fromRegistrationData(
            [ClaimsEnum::RedirectUris->value => ['https://example.org/cb']],
            RegistrationTypeEnum::FederatedAutomatic,
        );

        $this->assertSame(['openid'], array_values($client->getScopes()));
    }


    /**
     * An explicit but unsupported `scope` is NOT treated as "not specified": the unsupported values are dropped and
     * the client ends up with `openid` only - it does not receive the DCR default scope set.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromRegistrationDataWithUnsupportedScopeDoesNotApplyDcrDefaultScopes(): void
    {
        $this->moduleConfigMock->expects($this->never())->method('getDcrDefaultScopes');

        $client = $this->sut()->fromRegistrationData(
            [
                ClaimsEnum::RedirectUris->value => ['https://example.org/cb'],
                ClaimsEnum::Scope->value => 'unsupported_scope',
            ],
            RegistrationTypeEnum::Dynamic,
        );

        $this->assertSame(['openid'], array_values($client->getScopes()));
    }


    /**
     * An explicit, supported `scope` on a Dynamic registration is honored as-is and is not overridden by the DCR
     * default scope set.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromRegistrationDataHonorsExplicitScopeForDynamicRegistration(): void
    {
        $this->moduleConfigMock->expects($this->never())->method('getDcrDefaultScopes');

        $client = $this->sut()->fromRegistrationData(
            [
                ClaimsEnum::RedirectUris->value => ['https://example.org/cb'],
                ClaimsEnum::Scope->value => 'openid email',
            ],
            RegistrationTypeEnum::Dynamic,
        );

        $this->assertEqualsCanonicalizing(['openid', 'email'], array_values($client->getScopes()));
    }


    /**
     * A stored client row with a distinct value in every column it can have one, so that a value which
     * reached the wrong property is visible rather than coincidentally right. `fromState()` ends in a
     * call to `fromData()` passing twenty-five positional arguments, which is where a transposition
     * would hide.
     *
     * The three booleans are the exception, since three of them cannot hold three distinct values: here
     * `is_enabled` and `is_confidential` are both true, so a swap between those two -- which are
     * adjacent, arguments seven and eight -- is invisible in this fixture.
     * testFromStateHydratesEachBooleanColumnIndependently is what covers them.
     *
     * @param array<string,mixed> $overrides
     * @return array<string,mixed>
     */
    protected static function clientState(array $overrides = []): array
    {
        return array_merge(
            [
                ClientEntity::KEY_ID => 'stored-client-id',
                ClientEntity::KEY_SECRET => 'stored-client-secret',
                ClientEntity::KEY_NAME => 'Stored Client Name',
                ClientEntity::KEY_DESCRIPTION => 'Stored client description.',
                ClientEntity::KEY_AUTH_SOURCE => 'stored-auth-source',
                ClientEntity::KEY_REDIRECT_URI => '["https://example.org/stored-redirect"]',
                ClientEntity::KEY_SCOPES => '["openid","profile"]',
                ClientEntity::KEY_IS_ENABLED => true,
                ClientEntity::KEY_IS_CONFIDENTIAL => true,
                ClientEntity::KEY_OWNER => 'stored-owner@example.org',
                ClientEntity::KEY_POST_LOGOUT_REDIRECT_URI => '["https://example.org/stored-post-logout"]',
                ClientEntity::KEY_BACKCHANNEL_LOGOUT_URI => 'https://example.org/stored-backchannel',
                ClientEntity::KEY_ENTITY_IDENTIFIER => 'https://example.org/stored-entity',
                ClientEntity::KEY_CLIENT_REGISTRATION_TYPES => '["explicit"]',
                ClientEntity::KEY_FEDERATION_JWKS => '{"keys":[{"kid":"stored-federation-key"}]}',
                ClientEntity::KEY_JWKS => '{"keys":[{"kid":"stored-protocol-key"}]}',
                ClientEntity::KEY_JWKS_URI => 'https://example.org/stored-jwks',
                ClientEntity::KEY_SIGNED_JWKS_URI => 'https://example.org/stored-signed-jwks',
                ClientEntity::KEY_REGISTRATION_TYPE => RegistrationTypeEnum::FederatedAutomatic->value,
                ClientEntity::KEY_UPDATED_AT => '2024-03-04 05:06:07',
                ClientEntity::KEY_CREATED_AT => '2023-02-03 04:05:06',
                ClientEntity::KEY_EXPIRES_AT => '2025-04-05 06:07:08',
                ClientEntity::KEY_IS_GENERIC => false,
                ClientEntity::KEY_EXTRA_METADATA => '{"logo_uri":"https://example.org/stored-logo"}',
                ClientEntity::KEY_REGISTRATION_ACCESS_TOKEN => 'stored-registration-access-token-hash',
            ],
            $overrides,
        );
    }


    /**
     * A factory whose deployment salt and supported credential configurations are known, for the
     * generic Verifiable Credential Issuance client. Builds its own ModuleConfig so that two salts
     * can be compared within one test.
     *
     * @param string[] $credentialConfigurationIds
     */
    protected function sutForVci(
        string $secretSalt,
        array $credentialConfigurationIds = ['CredentialA'],
    ): ClientEntityFactory {
        $sspConfigMock = $this->createMock(Configuration::class);
        $sspConfigMock->method('getString')->willReturn($secretSalt);

        $moduleConfigMock = $this->createMock(ModuleConfig::class);
        $moduleConfigMock->method('sspConfig')->willReturn($sspConfigMock);
        $moduleConfigMock->method('getVciCredentialConfigurationIdsSupported')
            ->willReturn($credentialConfigurationIds);

        return new ClientEntityFactory($this->sspBridgeMock, $this->helpers, $moduleConfigMock);
    }


    /**
     * An existing client carrying a distinct value for each of the five fields which are taken from
     * registration metadata when present and inherited when not.
     */
    protected function existingFederatedClient(): ClientEntityInterface
    {
        return $this->sut()->fromData(
            id: 'existing-client',
            secret: 'existing-secret',
            name: 'Existing Client',
            description: '',
            redirectUri: ['https://example.org/cb'],
            scopes: ['openid'],
            isEnabled: true,
            backChannelLogoutUri: 'https://example.org/existing-backchannel',
            // Deliberately not the automatic default: `getClientRegistrationTypes()` returns that for
            // a client which has none, so inheritance which silently passed null would look identical.
            clientRegistrationTypes: [ClientRegistrationTypesEnum::Explicit->value],
            jwks: ['keys' => [['kid' => 'existing-key']]],
            jwksUri: 'https://example.org/existing-jwks',
            signedJwksUri: 'https://example.org/existing-signed-jwks',
            registrationType: RegistrationTypeEnum::FederatedAutomatic,
        );
    }


    /**
     * The five fields above, read back off a client.
     *
     * @return array<string,mixed>
     */
    protected static function inheritableMetadataFields(ClientEntityInterface $client): array
    {
        return [
            ClaimsEnum::BackChannelLogoutUri->value => $client->getBackChannelLogoutUri(),
            ClaimsEnum::ClientRegistrationTypes->value => $client->getClientRegistrationTypes(),
            ClaimsEnum::Jwks->value => $client->getJwks(),
            ClaimsEnum::JwksUri->value => $client->getJwksUri(),
            ClaimsEnum::SignedJwksUri->value => $client->getSignedJwksUri(),
        ];
    }


    /**
     * Every stored column has to land on its own property. This is the method every client goes
     * through on its way out of the database, and the only thing standing between a stored row and
     * the entity the rest of the module works with.
     *
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromStateHydratesEveryColumnOntoItsOwnProperty(): void
    {
        $client = $this->sut()->fromState(self::clientState());

        $this->assertSame('stored-client-id', $client->getIdentifier());
        $this->assertSame('stored-client-secret', $client->getSecret());
        $this->assertSame('Stored Client Name', $client->getName());
        $this->assertSame('Stored client description.', $client->getDescription());
        $this->assertSame('stored-auth-source', $client->getAuthSourceId());
        $this->assertSame(['https://example.org/stored-redirect'], $client->getRedirectUris());
        $this->assertSame(['openid', 'profile'], $client->getScopes());
        $this->assertTrue($client->isEnabled());
        $this->assertTrue($client->isConfidential());
        $this->assertSame('stored-owner@example.org', $client->getOwner());
        $this->assertSame(['https://example.org/stored-post-logout'], $client->getPostLogoutRedirectUri());
        $this->assertSame('https://example.org/stored-backchannel', $client->getBackChannelLogoutUri());
        $this->assertSame('https://example.org/stored-entity', $client->getEntityIdentifier());
        $this->assertSame(['explicit'], $client->getClientRegistrationTypes());
        $this->assertSame(['keys' => [['kid' => 'stored-federation-key']]], $client->getFederationJwks());
        $this->assertSame(['keys' => [['kid' => 'stored-protocol-key']]], $client->getJwks());
        $this->assertSame('https://example.org/stored-jwks', $client->getJwksUri());
        $this->assertSame('https://example.org/stored-signed-jwks', $client->getSignedJwksUri());
        $this->assertSame(RegistrationTypeEnum::FederatedAutomatic, $client->getRegistrationType());
        // Three timestamps of the same type, side by side in the argument list.
        $this->assertSame('2024-03-04 05:06:07', $client->getUpdatedAt()?->format('Y-m-d H:i:s'));
        $this->assertSame('2023-02-03 04:05:06', $client->getCreatedAt()?->format('Y-m-d H:i:s'));
        $this->assertSame('2025-04-05 06:07:08', $client->getExpiresAt()?->format('Y-m-d H:i:s'));
        $this->assertFalse($client->isGeneric());
        $this->assertSame(['logo_uri' => 'https://example.org/stored-logo'], $client->getExtraMetadata());
        $this->assertSame('stored-registration-access-token-hash', $client->getRegistrationAccessTokenHash());
    }


    /**
     * `is_enabled` and `is_confidential` are arguments seven and eight, adjacent and of the same type;
     * `is_generic` is argument twenty-three. Any two of them agreeing in a single fixture would make a
     * swap between those two invisible, and the shared fixture has to make two of them agree. Asserted
     * here across three states which each set exactly one of the three, so every one is pinned on its
     * own and any swap among them shows.
     *
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromStateHydratesEachBooleanColumnIndependently(): void
    {
        $enabledOnly = $this->sut()->fromState(self::clientState([
            ClientEntity::KEY_IS_ENABLED => true,
            ClientEntity::KEY_IS_CONFIDENTIAL => false,
            ClientEntity::KEY_IS_GENERIC => false,
        ]));
        $this->assertTrue($enabledOnly->isEnabled());
        $this->assertFalse($enabledOnly->isConfidential());
        $this->assertFalse($enabledOnly->isGeneric());

        $confidentialOnly = $this->sut()->fromState(self::clientState([
            ClientEntity::KEY_IS_ENABLED => false,
            ClientEntity::KEY_IS_CONFIDENTIAL => true,
            ClientEntity::KEY_IS_GENERIC => false,
        ]));
        $this->assertFalse($confidentialOnly->isEnabled());
        $this->assertTrue($confidentialOnly->isConfidential());
        $this->assertFalse($confidentialOnly->isGeneric());

        $genericOnly = $this->sut()->fromState(self::clientState([
            ClientEntity::KEY_IS_ENABLED => false,
            ClientEntity::KEY_IS_CONFIDENTIAL => false,
            ClientEntity::KEY_IS_GENERIC => true,
        ]));
        $this->assertFalse($genericOnly->isEnabled());
        $this->assertFalse($genericOnly->isConfidential());
        $this->assertTrue($genericOnly->isGeneric());
    }


    /**
     * Timestamps are stored without a zone and read back as UTC, which is the only reading that makes
     * an expiry comparison mean the same thing on two differently configured servers.
     *
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromStateReadsStoredTimestampsAsUtc(): void
    {
        $client = $this->sut()->fromState(self::clientState());

        $this->assertSame('UTC', $client->getCreatedAt()?->getTimezone()->getName());
        $this->assertSame('UTC', $client->getUpdatedAt()?->getTimezone()->getName());
        $this->assertSame('UTC', $client->getExpiresAt()?->getTimezone()->getName());
    }


    /**
     * `getState()` is what writes a client to storage and `fromState()` is what reads it back, so a
     * client which survives the round trip unchanged is the property that matters here.
     *
     * What this does NOT establish is that the first hydration was faithful to the stored row: a column
     * dropped or altered on the way in would be dropped or altered identically on the way back, and
     * both sides would agree. Neither would it catch a transposition, for the same reason.
     * testFromStateHydratesEveryColumnOntoItsOwnProperty is what holds the first hydration to the
     * stored values, field by field, and this test rests on that one having run.
     *
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromStateRoundTripsAClientThroughItsOwnStoredState(): void
    {
        $stored = $this->sut()->fromState(self::clientState());
        $reread = $this->sut()->fromState($stored->getState());

        $this->assertEquals($stored->getState(), $reread->getState());
    }


    /**
     * @return array<string,array{string}>
     */
    public static function requiredStateColumnProvider(): array
    {
        return [
            'identifier' => [ClientEntity::KEY_ID],
            'secret' => [ClientEntity::KEY_SECRET],
            'name' => [ClientEntity::KEY_NAME],
            'redirect uri' => [ClientEntity::KEY_REDIRECT_URI],
            'scopes' => [ClientEntity::KEY_SCOPES],
            'registration type' => [ClientEntity::KEY_REGISTRATION_TYPE],
        ];
    }


    /**
     * Each of the six required columns is guarded, and each on its own: a guard which only ever looked
     * at the first would still let a malformed row through as some other kind of failure further down.
     *
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    #[DataProvider('requiredStateColumnProvider')]
    public function testFromStateRejectsARequiredColumnWhichIsNotAString(string $column): void
    {
        $this->expectException(OidcServerException::class);
        $this->expectExceptionMessage('Invalid Client Entity state');

        $this->sut()->fromState(self::clientState([$column => 42]));
    }


    /**
     * An optional column which is empty means the client does not have that property, rather than
     * having it set to an empty string. The distinction matters: an empty `jwks_uri` fetched as a URL
     * would be a request to the OP itself.
     *
     * Note which layer enforces which. For the auth source, owner, back-channel logout URI and entity
     * identifier, `ClientEntity::__construct()` normalises an empty string to null itself, so the
     * matching guards in `fromState()` are belt and braces -- breaking one of them changes nothing
     * observable here. The rest of the assertions below do rest on `fromState()` alone.
     *
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromStateTreatsAnEmptyOptionalColumnAsUnset(): void
    {
        $client = $this->sut()->fromState(self::clientState([
            ClientEntity::KEY_AUTH_SOURCE => '',
            ClientEntity::KEY_OWNER => '',
            ClientEntity::KEY_BACKCHANNEL_LOGOUT_URI => '',
            ClientEntity::KEY_ENTITY_IDENTIFIER => '',
            ClientEntity::KEY_CLIENT_REGISTRATION_TYPES => '',
            ClientEntity::KEY_FEDERATION_JWKS => '',
            ClientEntity::KEY_JWKS => '',
            ClientEntity::KEY_JWKS_URI => '',
            ClientEntity::KEY_SIGNED_JWKS_URI => '',
            ClientEntity::KEY_UPDATED_AT => '',
            ClientEntity::KEY_CREATED_AT => '',
            ClientEntity::KEY_EXPIRES_AT => '',
            ClientEntity::KEY_EXTRA_METADATA => '',
            ClientEntity::KEY_REGISTRATION_ACCESS_TOKEN => '',
        ]));

        $this->assertNull($client->getAuthSourceId());
        $this->assertNull($client->getOwner());
        $this->assertNull($client->getBackChannelLogoutUri());
        $this->assertNull($client->getEntityIdentifier());
        $this->assertNull($client->getFederationJwks());
        $this->assertNull($client->getJwks());
        $this->assertNull($client->getJwksUri());
        $this->assertNull($client->getSignedJwksUri());
        $this->assertNull($client->getUpdatedAt());
        $this->assertNull($client->getCreatedAt());
        $this->assertNull($client->getExpiresAt());
        $this->assertNull($client->getRegistrationAccessTokenHash());
        $this->assertSame([], $client->getExtraMetadata());
        // Not null: a client which names no registration type is an automatic one.
        $this->assertSame([ClientRegistrationTypesEnum::Automatic->value], $client->getClientRegistrationTypes());
    }


    /**
     * A row which omits every column the method does not require still reads. `is_enabled` and
     * `is_generic` are supplied because `fromState()` reads them without a default, unlike every other
     * optional column; both are NOT NULL with a default in the schema, so a row out of storage always
     * carries them and the omission is not reachable from the database.
     *
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromStateAcceptsAStateWithOnlyTheColumnsItRequires(): void
    {
        $client = $this->sut()->fromState([
            ClientEntity::KEY_ID => 'minimal-client',
            ClientEntity::KEY_SECRET => 'minimal-secret',
            ClientEntity::KEY_NAME => 'Minimal Client',
            ClientEntity::KEY_REDIRECT_URI => '["https://example.org/cb"]',
            ClientEntity::KEY_SCOPES => '["openid"]',
            ClientEntity::KEY_REGISTRATION_TYPE => RegistrationTypeEnum::Manual->value,
            ClientEntity::KEY_IS_ENABLED => true,
            ClientEntity::KEY_IS_GENERIC => false,
        ]);

        $this->assertSame('minimal-client', $client->getIdentifier());
        $this->assertSame('', $client->getDescription());
        $this->assertSame([], $client->getPostLogoutRedirectUri());
        $this->assertFalse($client->isConfidential());
        $this->assertNull($client->getExpiresAt());
    }


    /**
     * Pinned rather than endorsed, and queued as a production fix. `post_logout_redirect_uri` is the one
     * optional JSON column read as `(string)($state[...] ?? "[]")` rather than
     * `empty($state[...]) ? null : ...`, and `??` coalesces only null. So a column holding an empty
     * string reaches `json_decode('')`, which under JSON_THROW_ON_ERROR throws, and hydrating the
     * client fails where every other empty optional column reads as unset.
     *
     * This is why that column is absent from the fixture in
     * testFromStateTreatsAnEmptyOptionalColumnAsUnset.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromStateFailsOnAnEmptyPostLogoutRedirectUriColumn(): void
    {
        $this->expectException(JsonException::class);

        $this->sut()->fromState(self::clientState([
            ClientEntity::KEY_POST_LOGOUT_REDIRECT_URI => '',
        ]));
    }


    /**
     * A null in that column is handled, which is what the schema allows it to hold.
     *
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromStateReadsANullPostLogoutRedirectUriColumnAsNoUris(): void
    {
        $client = $this->sut()->fromState(self::clientState([
            ClientEntity::KEY_POST_LOGOUT_REDIRECT_URI => null,
        ]));

        $this->assertSame([], $client->getPostLogoutRedirectUri());
    }


    /**
     * A column whose JSON is corrupt fails as a JsonException rather than silently becoming null,
     * which for the redirect URIs would turn a client with one registered URI into one with none.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromStateRejectsCorruptJsonInAStoredColumn(): void
    {
        $this->expectException(JsonException::class);

        $this->sut()->fromState(self::clientState([ClientEntity::KEY_REDIRECT_URI => 'not-json-at-all']));
    }


    /**
     * The stored value is trimmed before being resolved, so a column padded by whatever wrote it still
     * names its registration type.
     *
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromStateTrimsTheStoredRegistrationType(): void
    {
        $client = $this->sut()->fromState(self::clientState([
            ClientEntity::KEY_REGISTRATION_TYPE => '  ' . RegistrationTypeEnum::Dynamic->value . '  ',
        ]));

        $this->assertSame(RegistrationTypeEnum::Dynamic, $client->getRegistrationType());
    }


    /**
     * Pinned rather than endorsed, and queued as a production fix. A stored registration type which is
     * not one of the enum's cases raises a bare `ValueError` naming neither the client nor the column,
     * where every other malformed column in this method produces `Invalid Client Entity state`. Same
     * shape as the queued `getDcrRegistrationAuth()` fix.
     *
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromStateRaisesAValueErrorForAnUnknownStoredRegistrationType(): void
    {
        $this->expectException(ValueError::class);

        $this->sut()->fromState(self::clientState([
            ClientEntity::KEY_REGISTRATION_TYPE => 'no_such_registration_type',
        ]));
    }


    /**
     * The Verifiable Credential Issuance flows look this client up again by its identifier, so the
     * identifier has to be the same on every call for a given deployment. It is derived from the
     * deployment's secret salt, which must not be recoverable from it.
     *
     * @throws \Exception
     */
    public function testTheGenericVciClientIdentifierIsStableForADeployment(): void
    {
        // Two separate factories, because every request builds a fresh one: an identifier which were
        // merely stable within a single factory would still change from one request to the next, and
        // twice on one instance could not tell the two apart.
        $first = $this->sutForVci('deployment-secret-salt')->getGenericForVci();
        $second = $this->sutForVci('deployment-secret-salt')->getGenericForVci();

        $this->assertSame($first->getIdentifier(), $second->getIdentifier());
        // A full SHA-256 digest behind the prefix. Asserted as a shape rather than by repeating the
        // formula, so that a weakened or truncated digest fails while a rewrite of the same strength
        // does not.
        $this->assertMatchesRegularExpression('/^vci_[0-9a-f]{64}$/', $first->getIdentifier());
        $this->assertStringNotContainsString('deployment-secret-salt', $first->getIdentifier());
    }


    /**
     * Two deployments must not share this client's identifier, or one deployment's generic client
     * would be addressable on another.
     *
     * @throws \Exception
     */
    public function testTheGenericVciClientIdentifierChangesWithTheDeploymentSalt(): void
    {
        $this->assertNotSame(
            $this->sutForVci('salt-of-one-deployment')->getGenericForVci()->getIdentifier(),
            $this->sutForVci('salt-of-another-deployment')->getGenericForVci()->getIdentifier(),
        );
    }


    /**
     * The identifier is a deterministic function of the deployment salt; the secret must not be. A
     * salt-derived secret would be the same on every restart and reproducible by anyone holding the
     * salt, which is fine for an identifier -- identifiers are public -- and not for a secret.
     *
     * What this establishes is that the secret is fresh per construction and high-entropy, which is
     * what rules determinism out. It cannot distinguish a random secret from one mixing the salt with
     * fresh entropy, and does not need to: that second form is unpredictable too. Determinism is the
     * property that matters and the property asserted.
     *
     * @throws \Exception
     */
    public function testTheGenericVciClientSecretIsFreshRatherThanAFunctionOfTheSalt(): void
    {
        $fromOneDeployment = $this->sutForVci('deployment-secret-salt')->getGenericForVci();
        $fromTheSameSaltAgain = $this->sutForVci('deployment-secret-salt')->getGenericForVci();
        $fromAnotherDeployment = $this->sutForVci('another-deployment-salt')->getGenericForVci();

        // The decisive one: two factories given the SAME salt still produce different secrets, so the
        // secret cannot be a function of the salt. Freshness across two calls on one factory would not
        // establish that, since a salt plus a nonce is fresh every time and still salt-derived.
        $this->assertNotSame($fromOneDeployment->getSecret(), $fromTheSameSaltAgain->getSecret());
        $this->assertNotSame($fromOneDeployment->getSecret(), $fromAnotherDeployment->getSecret());

        // It is the random helper's output: hex, and long enough not to be guessed.
        $this->assertMatchesRegularExpression('/^[0-9a-f]{40,}$/', $fromOneDeployment->getSecret());
        $this->assertStringNotContainsString('deployment-secret-salt', $fromOneDeployment->getSecret());
        $this->assertNotSame($fromOneDeployment->getIdentifier(), $fromOneDeployment->getSecret());
    }


    /**
     * Each credential configuration is also a requestable scope of the same name, so the generic
     * client has to carry every one of them or the credentials it cannot name become unissuable
     * through it.
     *
     * @throws \Exception
     */
    public function testTheGenericVciClientCanRequestEveryCredentialConfiguration(): void
    {
        $client = $this->sutForVci('salt', ['CredentialA', 'CredentialB'])->getGenericForVci();

        $this->assertSame(['openid', 'CredentialA', 'CredentialB'], $client->getScopes());
    }


    /**
     * @throws \Exception
     */
    public function testTheGenericVciClientIsAnEnabledGenericWalletClient(): void
    {
        $client = $this->sutForVci('salt')->getGenericForVci();

        $this->assertTrue($client->isEnabled());
        $this->assertTrue($client->isGeneric());
        $this->assertSame(['openid-credential-offer://'], $client->getRedirectUris());
        $this->assertSame(RegistrationTypeEnum::Manual, $client->getRegistrationType());
        // A wallet holds no secret it can protect, so this is a public client.
        $this->assertFalse($client->isConfidential());
        // Both timestamps are set, and to the same instant: it has never been updated separately from
        // being created. Asserted as present first, since two nulls would compare equal too.
        $this->assertInstanceOf(DateTimeImmutable::class, $client->getCreatedAt());
        $this->assertInstanceOf(DateTimeImmutable::class, $client->getUpdatedAt());
        $this->assertEquals($client->getCreatedAt(), $client->getUpdatedAt());
        // A generic client is not issued with an expiry.
        $this->assertNull($client->getExpiresAt());
    }


    /**
     * An explicitly requested implicit grant is one of the four indications of a public client, and
     * the only one nothing was exercising.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromRegistrationDataDerivesPublicTypeFromImplicitGrantType(): void
    {
        $client = $this->sut()->fromRegistrationData(
            [
                ClaimsEnum::RedirectUris->value => ['https://example.org/cb'],
                ClaimsEnum::GrantTypes->value => [GrantTypesEnum::Implicit->value],
            ],
            RegistrationTypeEnum::Dynamic,
        );

        $this->assertFalse($client->isConfidential());
    }


    /**
     * @return array<string,array{string,mixed}>
     */
    public static function metadataOverExistingClientProvider(): array
    {
        return [
            'backchannel logout uri' => [
                ClaimsEnum::BackChannelLogoutUri->value,
                'https://example.org/from-metadata-backchannel',
            ],
            'client registration types' => [
                ClaimsEnum::ClientRegistrationTypes->value,
                [
                    ClientRegistrationTypesEnum::Explicit->value,
                    ClientRegistrationTypesEnum::Automatic->value,
                ],
            ],
            'jwks' => [
                ClaimsEnum::Jwks->value,
                ['keys' => [['kid' => 'from-metadata-key']]],
            ],
            'jwks uri' => [
                ClaimsEnum::JwksUri->value,
                'https://example.org/from-metadata-jwks',
            ],
            'signed jwks uri' => [
                ClaimsEnum::SignedJwksUri->value,
                'https://example.org/from-metadata-signed-jwks',
            ],
        ];
    }


    /**
     * Each of these five fields is taken from the registration metadata when it is there and inherited
     * from the existing client when it is not. Supplying one of them must move that one and nothing
     * else: five neighbouring ternaries reading five neighbouring claims is exactly where a field
     * would end up resolved from its neighbour without anything looking wrong.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    #[DataProvider('metadataOverExistingClientProvider')]
    public function testFromRegistrationDataTakesOnlyTheSuppliedFieldFromMetadata(
        string $claim,
        mixed $value,
    ): void {
        $existingClient = $this->existingFederatedClient();

        $client = $this->sut()->fromRegistrationData(
            [
                ClaimsEnum::RedirectUris->value => ['https://example.org/cb'],
                $claim => $value,
            ],
            RegistrationTypeEnum::FederatedAutomatic,
            existingClient: $existingClient,
        );

        $inherited = self::inheritableMetadataFields($existingClient);

        foreach (self::inheritableMetadataFields($client) as $resolvedClaim => $resolvedValue) {
            if ($resolvedClaim === $claim) {
                $this->assertSame(
                    $value,
                    $resolvedValue,
                    sprintf('"%s" was not taken from the registration metadata.', $claim),
                );
                continue;
            }

            $this->assertSame(
                $inherited[$resolvedClaim],
                $resolvedValue,
                sprintf('Supplying "%s" also changed "%s".', $claim, $resolvedClaim),
            );
        }
    }


    /**
     * A `jwks` present but carrying no keys is not a key set, so it must not displace the one the
     * client already has. Registration metadata routinely carries an empty container.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFromRegistrationDataIgnoresAnEmptyJwksInMetadata(): void
    {
        $existingClient = $this->existingFederatedClient();

        $client = $this->sut()->fromRegistrationData(
            [
                ClaimsEnum::RedirectUris->value => ['https://example.org/cb'],
                ClaimsEnum::Jwks->value => [ClaimsEnum::Keys->value => []],
            ],
            RegistrationTypeEnum::FederatedAutomatic,
            existingClient: $existingClient,
        );

        $this->assertSame($existingClient->getJwks(), $client->getJwks());
    }
}
