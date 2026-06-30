<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Factories\Entities;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Bridges\SspBridge\Utils;
use SimpleSAML\Module\oidc\Codebooks\RegistrationTypeEnum;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Factories\Entities\ClientEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\ErrorsEnum;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairBag;
use SimpleSAML\Utils\Random;

#[CoversClass(ClientEntityFactory::class)]
#[UsesClass(ClientEntity::class)]
class ClientEntityFactoryTest extends TestCase
{
    protected MockObject $sspBridgeMock;
    protected MockObject $moduleConfigMock;
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
}
