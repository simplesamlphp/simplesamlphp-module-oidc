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
        $this->moduleConfigMock->method('getScopes')->willReturn(['openid' => ['description' => 'openid']]);

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
}
