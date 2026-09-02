<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers\VerifiableCredentials;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Codebooks\VciCredentialBindingPolicyEnum;
use SimpleSAML\Module\oidc\Controllers\VerifiableCredentials\CredentialIssuerConfigurationController;
use SimpleSAML\Module\oidc\Factories\DidFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\Module\oidc\Utils\VciContextResolver;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\CredentialFormatIdentifiersEnum;
use SimpleSAML\OpenID\Did;
use SimpleSAML\OpenID\ValueAbstracts\KeyPair;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPair;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairBag;
use Symfony\Component\HttpFoundation\JsonResponse;

#[CoversClass(CredentialIssuerConfigurationController::class)]
#[AllowMockObjectsWithoutExpectations]
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

    protected MockObject $didMock;

    protected MockObject $didFactoryMock;

    protected SignatureKeyPairBag $vciSignatureKeyPairBag;

    protected VciCredentialBindingPolicyEnum $bindingPolicy;

    /**
     * What the resolver registry reports it can resolve, which is what the metadata is filtered from.
     *
     * @var list<string>
     */
    protected array $resolvableDidMethods;


    protected function setUp(): void
    {
        $this->bindingPolicy = VciCredentialBindingPolicyEnum::ProofBound;
        $this->resolvableDidMethods = ['did:jwk', 'did:key', 'did:web'];
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->routesMock = $this->createMock(Routes::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        $this->vciContextResolverMock = $this->createMock(VciContextResolver::class);
        $this->didMock = $this->createMock(Did::class);
        $this->didFactoryMock = $this->createMock(DidFactory::class);

        $this->didMock->method('supportedMethods')
            ->willReturnCallback(fn(): array => $this->resolvableDidMethods);
        $this->didFactoryMock->method('build')->willReturn($this->didMock);

        $this->moduleConfigMock->method('getVciEnabled')->willReturn(true);
        $this->moduleConfigMock->method('getIssuer')->willReturn(self::ISSUER);
        $this->moduleConfigMock->method('getOrganizationName')->willReturn('Example University');
        $this->moduleConfigMock->method('getDescription')->willReturn('Example credentials');
        $this->moduleConfigMock->method('getLogoUri')->willReturn('https://issuer.com/logo.png');
        $this->moduleConfigMock->method('getVciCredentialConfigurationsSupported')
            ->willReturn($this->credentialConfigurations());
        $this->moduleConfigMock->method('getVciCredentialBindingPolicyFor')
            ->willReturnCallback(fn(): VciCredentialBindingPolicyEnum => $this->bindingPolicy);

        // Two pairs differing in algorithm, so that an assertion on the advertised algorithm can tell
        // the active signing key apart from merely "one of the configured ones".
        $this->vciSignatureKeyPairBag = new SignatureKeyPairBag(
            $this->buildSignatureKeyPair('vci-01', SignatureAlgorithmEnum::ES256),
            $this->buildSignatureKeyPair('vci-02', SignatureAlgorithmEnum::RS256),
        );
        $this->moduleConfigMock->method('getActiveVciSignatureKeyPair')
            ->willReturnCallback(fn(): SignatureKeyPair => $this->vciSignatureKeyPairBag->getFirstOrFail());

        $this->routesMock->method('urlCredentialIssuerCredential')->willReturn(self::CREDENTIAL_ENDPOINT);
        $this->routesMock->method('urlCredentialIssuerNonce')->willReturn(self::NONCE_ENDPOINT);
        $this->routesMock->method('newJsonResponse')->willReturnCallback(
            /**
             * @param ?array<array-key,mixed> $data
             */
            static fn(?array $data = null): JsonResponse => new JsonResponse($data),
        );
    }


    protected function buildSignatureKeyPair(string $keyId, SignatureAlgorithmEnum $algorithm): SignatureKeyPair
    {
        $keyPairMock = $this->createMock(KeyPair::class);
        $keyPairMock->method('getKeyId')->willReturn($keyId);

        $signatureKeyPairMock = $this->createMock(SignatureKeyPair::class);
        $signatureKeyPairMock->method('getKeyPair')->willReturn($keyPairMock);
        $signatureKeyPairMock->method('getSignatureAlgorithm')->willReturn($algorithm);

        return $signatureKeyPairMock;
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
            $this->didFactoryMock,
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
        // Every method the resolver registry reports, in its order, plus `jwk` - because a key proof
        // may carry its key inline and this configuration accepts one. A wallet has no other way to
        // find that out.
        $this->assertSame(
            ['did:jwk', 'did:key', 'did:web', 'jwk'],
            $configuration[ClaimsEnum::CryptographicBindingMethodsSupported->value],
        );
        $this->assertArrayHasKey(ClaimsEnum::ProofTypesSupported->value, $configuration);
        // What the operator configured is still there, with the above added rather than substituted.
        $this->assertSame('UniversityDegree', $configuration[ClaimsEnum::Scope->value]);
    }


    /**
     * A DIIP configuration accepts holders identified by the two methods that profile names, and the
     * metadata has to say which those are rather than repeating what every other configuration accepts.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testADiipConfigurationAdvertisesOnlyTheMethodsItAccepts(): void
    {
        $this->bindingPolicy = VciCredentialBindingPolicyEnum::DiipProofBound;

        $metadata = $this->publishedMetadata();

        /** @var array<string,array<string,mixed>> $configurations */
        $configurations = $metadata[ClaimsEnum::CredentialConfigurationsSupported->value];
        $configuration = $configurations[self::CONFIGURATION_ID];

        // No `jwk` here, unlike the default policy: this one refuses a key proof carrying its key
        // inline, so advertising the value would invite a proof it would then turn away.
        $this->assertSame(
            ['did:jwk', 'did:web'],
            $configuration[ClaimsEnum::CryptographicBindingMethodsSupported->value],
        );
        // It is a key-proof configuration like any other, so both binding fields are present and the
        // batch size is advertised.
        $this->assertArrayHasKey(ClaimsEnum::ProofTypesSupported->value, $configuration);
        $this->assertArrayHasKey(ClaimsEnum::BatchCredentialIssuance->value, $metadata);
    }


    /**
     * The point of taking the list from the resolver registry rather than writing it out here.
     *
     * A DID method the library gains is one this deployment can resolve the moment it is upgraded, so
     * the default policy accepts a holder using it and has to say so. The DIIP policy does not, and its
     * advertisement must not widen along with the registry.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testAMethodTheRegistryGainsIsAdvertisedOnlyWhereItIsAccepted(): void
    {
        $this->resolvableDidMethods = ['did:jwk', 'did:key', 'did:web', 'did:example'];

        /** @var array<string,array<string,mixed>> $configurations */
        $configurations = $this->publishedMetadata()[ClaimsEnum::CredentialConfigurationsSupported->value];

        $this->assertSame(
            ['did:jwk', 'did:key', 'did:web', 'did:example', 'jwk'],
            $configurations[self::CONFIGURATION_ID][ClaimsEnum::CryptographicBindingMethodsSupported->value],
        );

        $this->bindingPolicy = VciCredentialBindingPolicyEnum::DiipProofBound;

        /** @var array<string,array<string,mixed>> $configurations */
        $configurations = $this->publishedMetadata()[ClaimsEnum::CredentialConfigurationsSupported->value];

        $this->assertSame(
            ['did:jwk', 'did:web'],
            $configurations[self::CONFIGURATION_ID][ClaimsEnum::CryptographicBindingMethodsSupported->value],
        );
    }


    /**
     * A deployment binding nothing has no use for the resolver registry, and building it is what reads
     * this deployment's DID settings and instantiates its cache adapter. Publishing this document must
     * not depend on either, so the facade is never built for such a deployment.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testTheDidFacadeIsNotBuiltForAConfigurationWhichBindsNothing(): void
    {
        $this->bindingPolicy = VciCredentialBindingPolicyEnum::Proofless;

        $this->didFactoryMock->expects($this->never())->method('build');

        $this->publishedMetadata();
    }


    /**
     * And it is built once for the whole document rather than once per credential configuration, since
     * every one of them is filtered from the same registry.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testTheDidFacadeIsBuiltOnceHoweverManyConfigurationsBind(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getVciEnabled')->willReturn(true);
        $this->moduleConfigMock->method('getVciCredentialBindingPolicyFor')
            ->willReturn(VciCredentialBindingPolicyEnum::ProofBound);
        $this->moduleConfigMock->method('getActiveVciSignatureKeyPair')
            ->willReturnCallback(fn(): SignatureKeyPair => $this->vciSignatureKeyPairBag->getFirstOrFail());
        $this->moduleConfigMock->method('getVciCredentialConfigurationsSupported')->willReturn([
            self::CONFIGURATION_ID => [
                ClaimsEnum::Format->value => CredentialFormatIdentifiersEnum::JwtVcJson->value,
            ],
            'SecondCredential' => [
                ClaimsEnum::Format->value => CredentialFormatIdentifiersEnum::JwtVcJson->value,
            ],
        ]);

        $this->didFactoryMock->expects($this->once())->method('build')->willReturn($this->didMock);

        $this->publishedMetadata();
    }


    /**
     * The other direction: a method the profile names but this deployment can not resolve is not
     * advertised, because a wallet acting on it would have its proof refused at the Credential
     * Endpoint.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testAMethodTheRegistryCanNotResolveIsNotAdvertised(): void
    {
        $this->bindingPolicy = VciCredentialBindingPolicyEnum::DiipProofBound;
        $this->resolvableDidMethods = ['did:jwk', 'did:key'];

        /** @var array<string,array<string,mixed>> $configurations */
        $configurations = $this->publishedMetadata()[ClaimsEnum::CredentialConfigurationsSupported->value];

        $this->assertSame(
            ['did:jwk'],
            $configurations[self::CONFIGURATION_ID][ClaimsEnum::CryptographicBindingMethodsSupported->value],
        );
    }


    /**
     * The credential endpoint refuses a `proofs` array longer than this, so a wallet has to be able to
     * find out what the limit is before it builds one.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testPublishesTheBatchSizeItActuallyEnforces(): void
    {
        $metadata = $this->publishedMetadata();

        $this->assertSame(
            [ClaimsEnum::BatchSize->value => ModuleConfig::VCI_BATCH_SIZE],
            $metadata[ClaimsEnum::BatchCredentialIssuance->value] ?? null,
        );
    }


    /**
     * A configuration issuing credentials which are not bound to a wallet key must advertise neither
     * binding field, not just one of them.
     *
     * OpenID4VCI requires `proof_types_supported` wherever `cryptographic_binding_methods_supported`
     * appears, and requires a Credential Request to carry `proofs` wherever `proof_types_supported`
     * appears. So leaving either behind would either produce a malformed document or promise a binding
     * this configuration does not perform, which is exactly the state this module used to publish.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testAProoflessConfigurationAdvertisesNoBindingAtAll(): void
    {
        $this->bindingPolicy = VciCredentialBindingPolicyEnum::Proofless;

        $metadata = $this->publishedMetadata();

        /** @var array<string,array<string,mixed>> $configurations */
        $configurations = $metadata[ClaimsEnum::CredentialConfigurationsSupported->value];
        $configuration = $configurations[self::CONFIGURATION_ID];

        $this->assertArrayNotHasKey(ClaimsEnum::CryptographicBindingMethodsSupported->value, $configuration);
        $this->assertArrayNotHasKey(ClaimsEnum::ProofTypesSupported->value, $configuration);

        // Batching is something key proofs do, so an issuer with nothing to prove against advertises no
        // batch size either.
        $this->assertArrayNotHasKey(ClaimsEnum::BatchCredentialIssuance->value, $metadata);

        // The rest of the configuration is published exactly as before.
        $this->assertSame('UniversityDegree', $configuration[ClaimsEnum::Scope->value]);
    }


    /**
     * A binding field the operator wrote into the credential configuration itself is republished
     * verbatim, so a proofless configuration has to have it taken out rather than merely not added.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testAProoflessConfigurationDropsBindingFieldsTheOperatorWroteIn(): void
    {
        $moduleConfigMock = $this->createMock(ModuleConfig::class);
        $moduleConfigMock->method('getVciEnabled')->willReturn(true);
        $moduleConfigMock->method('getVciCredentialBindingPolicyFor')
            ->willReturn(VciCredentialBindingPolicyEnum::Proofless);
        $moduleConfigMock->method('getActiveVciSignatureKeyPair')
            ->willReturn($this->vciSignatureKeyPairBag->getFirstOrFail());
        $moduleConfigMock->method('getVciCredentialConfigurationsSupported')->willReturn([
            self::CONFIGURATION_ID => [
                ClaimsEnum::Format->value => CredentialFormatIdentifiersEnum::JwtVcJson->value,
                ClaimsEnum::CryptographicBindingMethodsSupported->value => ['did:jwk'],
                ClaimsEnum::ProofTypesSupported->value => ['jwt' => []],
            ],
        ]);

        $controller = new CredentialIssuerConfigurationController(
            $moduleConfigMock,
            $this->routesMock,
            $this->loggerServiceMock,
            $this->vciContextResolverMock,
            $this->didFactoryMock,
        );

        $content = $controller->configuration()->getContent();
        $this->assertIsString($content);
        /** @var array<array-key,mixed> $metadata */
        $metadata = json_decode($content, true, 512, JSON_THROW_ON_ERROR);

        /** @var array<string,array<string,mixed>> $configurations */
        $configurations = $metadata[ClaimsEnum::CredentialConfigurationsSupported->value];
        $configuration = $configurations[self::CONFIGURATION_ID];

        $this->assertArrayNotHasKey(ClaimsEnum::CryptographicBindingMethodsSupported->value, $configuration);
        $this->assertArrayNotHasKey(ClaimsEnum::ProofTypesSupported->value, $configuration);
    }


    /**
     * A wallet is told which algorithm a credential will come back signed with, and that has to be the
     * algorithm of the key which will actually sign it. The two are separate calls made by separate
     * classes, so nothing but asking the same question keeps them together.
     *
     * More than one key pair is configured here, so an implementation which advertised every configured
     * algorithm, or a different one of them, fails this rather than passing for want of an alternative.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     * @throws \SimpleSAML\OpenID\Exceptions\OpenIdException
     */
    public function testAdvertisesTheAlgorithmOfTheActiveSigningKeyOnly(): void
    {
        $activeSignatureKeyPair = $this->vciSignatureKeyPairBag->getFirstOrFail();
        $this->assertGreaterThan(1, count($this->vciSignatureKeyPairBag->getAllAlgorithmNamesUnique()));

        $metadata = $this->publishedMetadata();

        /** @var array<string,array<string,mixed>> $configurations */
        $configurations = $metadata[ClaimsEnum::CredentialConfigurationsSupported->value];
        $this->assertNotEmpty($configurations);

        foreach ($configurations as $configuration) {
            $this->assertSame(
                [$activeSignatureKeyPair->getSignatureAlgorithm()->value],
                $configuration[ClaimsEnum::CredentialSigningAlgValuesSupported->value],
            );
        }
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
            $this->didFactoryMock,
        );
    }
}
