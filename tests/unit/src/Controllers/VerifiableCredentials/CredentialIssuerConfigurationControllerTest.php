<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers\VerifiableCredentials;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Controllers\VerifiableCredentials\CredentialIssuerConfigurationController;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\Module\oidc\Utils\VciContextResolver;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\CredentialFormatIdentifiersEnum;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPair;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairBag;
use Symfony\Component\HttpFoundation\JsonResponse;

#[CoversClass(CredentialIssuerConfigurationController::class)]
class CredentialIssuerConfigurationControllerTest extends TestCase
{
    protected const string CONFIGURATION_ID = 'UniversityDegreeCredential';

    protected const string ISSUER = 'https://issuer.com';

    protected const string CREDENTIAL_ENDPOINT = 'https://issuer.com/credential';

    protected const string NONCE_ENDPOINT = 'https://issuer.com/nonce';

    /**
     * Every getter through which a private Status List control could reach this controller.
     *
     * The published document is wallet visible, and these settings are not: which pool a configuration
     * allocates from, how its lists are keyed, how long its credentials live, and how the lists are
     * wound down are the deployment's business and say something about its revocation practice. They
     * are kept in top level options precisely so that returning `credential_configurations_supported`
     * wholesale can not carry them out, and this list is what checks that nothing started reading them
     * here.
     */
    protected const array PRIVATE_STATUS_LIST_GETTERS = [
        'getVciStatusListEnabled',
        'getVciStatusListPoolBag',
        'getVciStatusListPoolFor',
        'getVciStatusListKeyProfile',
        'getVciCredentialTtls',
        'getVciCredentialTtlFor',
        'getVciStatusListRetirementGrace',
        'getVciStatusListAuditRetention',
        'getVciStatusListRequestsPerMinute',
    ];

    protected MockObject $moduleConfigMock;
    protected MockObject $routesMock;
    protected MockObject $loggerServiceMock;
    protected MockObject $vciContextResolverMock;

    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->routesMock = $this->createMock(Routes::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        $this->vciContextResolverMock = $this->createMock(VciContextResolver::class);

        $this->moduleConfigMock->method('getVciEnabled')->willReturn(true);
        $this->moduleConfigMock->method('getIssuer')->willReturn(self::ISSUER);
        $this->moduleConfigMock->method('getOrganizationName')->willReturn('Example University');
        $this->moduleConfigMock->method('getDescription')->willReturn('Example credentials');
        $this->moduleConfigMock->method('getLogoUri')->willReturn('https://issuer.com/logo.png');
        $this->moduleConfigMock->method('getVciCredentialConfigurationsSupported')
            ->willReturn($this->credentialConfigurations());

        $signatureKeyPairMock = $this->createMock(SignatureKeyPair::class);
        $signatureKeyPairMock->method('getSignatureAlgorithm')->willReturn(SignatureAlgorithmEnum::ES256);
        $signatureKeyPairBagMock = $this->createMock(SignatureKeyPairBag::class);
        $signatureKeyPairBagMock->method('getFirstOrFail')->willReturn($signatureKeyPairMock);
        $this->moduleConfigMock->method('getVciSignatureKeyPairBag')->willReturn($signatureKeyPairBagMock);

        $this->routesMock->method('urlCredentialIssuerCredential')->willReturn(self::CREDENTIAL_ENDPOINT);
        $this->routesMock->method('urlCredentialIssuerNonce')->willReturn(self::NONCE_ENDPOINT);
        $this->routesMock->method('newJsonResponse')->willReturnCallback(
            /**
             * @param ?array<array-key,mixed> $data
             */
            static fn(?array $data = null): JsonResponse => new JsonResponse($data),
        );
    }

    /**
     * @return array<string,array<string,mixed>>
     */
    protected function credentialConfigurations(): array
    {
        return [
            self::CONFIGURATION_ID => [
                ClaimsEnum::Format->value => CredentialFormatIdentifiersEnum::JwtVcJson->value,
                ClaimsEnum::Scope->value => 'UniversityDegree',
            ],
        ];
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    protected function sut(): CredentialIssuerConfigurationController
    {
        return new CredentialIssuerConfigurationController(
            $this->moduleConfigMock,
            $this->routesMock,
            $this->loggerServiceMock,
            $this->vciContextResolverMock,
        );
    }

    /**
     * @return array<array-key,mixed>
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    protected function publishedMetadata(): array
    {
        $content = $this->sut()->configuration()->getContent();

        $this->assertIsString($content);

        /** @var array<array-key,mixed> $decoded */
        $decoded = json_decode($content, true, 512, JSON_THROW_ON_ERROR);

        return $decoded;
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testPublishesTheIssuerAndItsEndpoints(): void
    {
        $metadata = $this->publishedMetadata();

        $this->assertSame(self::ISSUER, $metadata[ClaimsEnum::CredentialIssuer->value]);
        $this->assertSame(self::CREDENTIAL_ENDPOINT, $metadata[ClaimsEnum::CredentialEndpoint->value]);
        $this->assertSame(self::NONCE_ENDPOINT, $metadata[ClaimsEnum::NonceEndpoint->value]);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testDescribesWhatEachConfigurationCanBeProvedAndSignedWith(): void
    {
        $metadata = $this->publishedMetadata();

        /** @var array<string,array<string,mixed>> $configurations */
        $configurations = $metadata[ClaimsEnum::CredentialConfigurationsSupported->value];
        $configuration = $configurations[self::CONFIGURATION_ID];

        $this->assertSame(
            [SignatureAlgorithmEnum::ES256->value],
            $configuration[ClaimsEnum::CredentialSigningAlgValuesSupported->value],
        );
        $this->assertSame(
            ['did:key', 'did:jwk'],
            $configuration[ClaimsEnum::CryptographicBindingMethodsSupported->value],
        );
        $this->assertArrayHasKey(ClaimsEnum::ProofTypesSupported->value, $configuration);
        // What the operator configured is still there, with the above added rather than substituted.
        $this->assertSame('UniversityDegree', $configuration[ClaimsEnum::Scope->value]);
    }

    /**
     * The document goes to wallets, so nothing about how this deployment runs its Status Lists may be
     * in it.
     *
     * `credential_configurations_supported` is republished wholesale, so a private control placed
     * inside one would be handed out with it. That is why they are top level options instead, and this
     * asserts the arrangement rather than trusting it: no getter which could carry one is reached
     * while the document is built.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testPublishesNoStatusListControls(): void
    {
        foreach (self::PRIVATE_STATUS_LIST_GETTERS as $getter) {
            $this->moduleConfigMock->expects($this->never())->method($getter);
        }

        $metadata = $this->publishedMetadata();

        $encoded = json_encode($metadata, JSON_THROW_ON_ERROR);

        foreach (
            [
                ModuleConfig::OPTION_VCI_STATUS_LIST_ENABLED,
                ModuleConfig::OPTION_VCI_STATUS_LIST_KEY_PROFILE,
                ModuleConfig::OPTION_VCI_STATUS_LIST_POOLS,
                ModuleConfig::OPTION_VCI_STATUS_LIST_REQUESTS_PER_MINUTE,
                ModuleConfig::OPTION_VCI_STATUS_LIST_RETIREMENT_GRACE,
                ModuleConfig::OPTION_VCI_STATUS_LIST_AUDIT_RETENTION,
                ModuleConfig::OPTION_VCI_CREDENTIAL_TTLS,
            ] as $option
        ) {
            $this->assertStringNotContainsString($option, $encoded);
        }

        // The specification registers no "status lists are supported" parameter, and support is
        // discovered from the `status` claim of an issued credential instead. Anything resembling one
        // here would be invented rather than published.
        $this->assertStringNotContainsString('status_list', $encoded);
    }

    /**
     * The constructor is the gate: with Verifiable Credentials switched off there is no metadata to
     * publish, and nothing further in this controller should be reachable.
     */
    public function testRefusesToPublishAnythingWhenCredentialsAreDisabled(): void
    {
        $moduleConfigMock = $this->createMock(ModuleConfig::class);
        $moduleConfigMock->method('getVciEnabled')->willReturn(false);
        $moduleConfigMock->expects($this->never())->method('getVciCredentialConfigurationsSupported');

        $this->loggerServiceMock->expects($this->once())->method('warning');

        $this->expectException(OidcServerException::class);

        new CredentialIssuerConfigurationController(
            $moduleConfigMock,
            $this->routesMock,
            $this->loggerServiceMock,
            $this->vciContextResolverMock,
        );
    }
}
