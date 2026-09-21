<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Services;

use Jose\Component\Core\JWK as JoseJwk;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\Codebooks\VciIssuerIdentifierModeEnum;
use SimpleSAML\Module\oidc\Exceptions\OidcException;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\VcIssuerMetadataService;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\VciIssuerIdentifier;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\VciIssuerIdentity;
use SimpleSAML\Module\oidc\VerifiableCredentials\VciIssuerIdentityResolver;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Jwk;
use SimpleSAML\OpenID\Jwk\Factories\JwkDecoratorFactory;
use SimpleSAML\OpenID\Jwk\JwkDecorator;
use SimpleSAML\OpenID\Jwks;
use SimpleSAML\OpenID\Jwks\Factories\JwksDecoratorFactory;
use SimpleSAML\OpenID\ValueAbstracts\KeyPair;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPair;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairBag;

#[CoversClass(VcIssuerMetadataService::class)]
#[AllowMockObjectsWithoutExpectations]
class VcIssuerMetadataServiceTest extends TestCase
{
    protected const string DID_WEB = 'did:web:issuer.com';

    /**
     * The public members of each configured pair, keyed by the pair's own key id. Real JWK values with
     * the `use` and `alg` the key pair factory decorates production keys with, since what the published
     * set does to them is the thing under test.
     */
    protected const array PUBLIC_JWKS = [
        'vci-01' => [
            'kty' => 'EC', 'crv' => 'P-256', 'x' => 'x-one', 'y' => 'y-one',
            'kid' => 'vci-01', 'use' => 'sig', 'alg' => 'ES256',
        ],
        'vci-02' => [
            'kty' => 'EC', 'crv' => 'P-256', 'x' => 'x-two', 'y' => 'y-two',
            'kid' => 'vci-02', 'use' => 'sig', 'alg' => 'ES256',
        ],
    ];


    protected MockObject $moduleConfigMock;

    protected MockObject $jwkMock;

    protected MockObject $jwksMock;

    protected MockObject $vciIssuerIdentityResolverMock;

    protected VciIssuerIdentifier $issuerIdentifier;

    protected SignatureKeyPairBag $vciSignatureKeyPairBag;

    /** @var list<array{identifier: \SimpleSAML\Module\oidc\VerifiableCredentials\Values\VciIssuerIdentifier, keyId: string}> */
    protected array $resolutions = [];


    protected function setUp(): void
    {
        $this->resolutions = [];
        $this->issuerIdentifier = new VciIssuerIdentifier(VciIssuerIdentifierModeEnum::DidJwk);
        $this->vciSignatureKeyPairBag = new SignatureKeyPairBag(
            $this->buildSignatureKeyPair('vci-01'),
            $this->buildSignatureKeyPair('vci-02'),
        );

        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getVciIssuerIdentifier')
            ->willReturnCallback(fn(): VciIssuerIdentifier => $this->issuerIdentifier);
        $this->moduleConfigMock->method('getVciSignatureKeyPairBag')
            ->willReturnCallback(fn(): SignatureKeyPairBag => $this->vciSignatureKeyPairBag);

        // Real factories behind mocked facades, so that the set is built and serialised the way it
        // would be in production rather than echoed back by a stub.
        $this->jwkMock = $this->createMock(Jwk::class);
        $this->jwkMock->method('jwkDecoratorFactory')->willReturn(new JwkDecoratorFactory());
        $this->jwksMock = $this->createMock(Jwks::class);
        $this->jwksMock->method('jwksDecoratorFactory')->willReturn(new JwksDecoratorFactory());

        // Names a pair's key the way each identity mode does, and records what it was asked. The
        // shapes are the resolver's own (see VciIssuerIdentityResolverTest); what is under test here is
        // that the service asks for the right ones and publishes what it is told.
        $this->vciIssuerIdentityResolverMock = $this->createMock(VciIssuerIdentityResolver::class);
        $this->vciIssuerIdentityResolverMock->method('resolve')->willReturnCallback(
            function (VciIssuerIdentifier $identifier, SignatureKeyPair $signatureKeyPair): VciIssuerIdentity {
                $keyId = $signatureKeyPair->getKeyPair()->getKeyId();
                $this->resolutions[] = ['identifier' => $identifier, 'keyId' => $keyId];

                return match ($identifier->getMode()) {
                    VciIssuerIdentifierModeEnum::DidJwk => new VciIssuerIdentity(
                        VciIssuerIdentifierModeEnum::DidJwk,
                        'did:jwk:' . $keyId,
                        'did:jwk:' . $keyId . '#0',
                    ),
                    VciIssuerIdentifierModeEnum::DidWeb => new VciIssuerIdentity(
                        VciIssuerIdentifierModeEnum::DidWeb,
                        (string)$identifier->getDidWeb(),
                        $identifier->getDidWeb() . '#' . $keyId,
                    ),
                    VciIssuerIdentifierModeEnum::Https => new VciIssuerIdentity(
                        VciIssuerIdentifierModeEnum::Https,
                        'https://issuer.com',
                        $keyId,
                    ),
                };
            },
        );
    }


    protected function buildSignatureKeyPair(string $keyId): SignatureKeyPair
    {
        $keyPairMock = $this->createMock(KeyPair::class);
        $keyPairMock->method('getKeyId')->willReturn($keyId);
        $keyPairMock->method('getPublicKey')->willReturn(new JwkDecorator(new JoseJwk(self::PUBLIC_JWKS[$keyId])));

        $signatureKeyPairMock = $this->createMock(SignatureKeyPair::class);
        $signatureKeyPairMock->method('getKeyPair')->willReturn($keyPairMock);

        return $signatureKeyPairMock;
    }


    protected function sut(): VcIssuerMetadataService
    {
        return new VcIssuerMetadataService(
            $this->moduleConfigMock,
            $this->jwkMock,
            $this->jwksMock,
            $this->vciIssuerIdentityResolverMock,
        );
    }


    /**
     * The published set as a wallet or verifier reads it, through the JSON it is published as.
     *
     * @return list<array<string,mixed>>
     * @throws \JsonException
     */
    protected function publishedKeys(): array
    {
        /** @var array{jwks: array{keys: list<array<string,mixed>>}} $decoded */
        $decoded = json_decode(
            json_encode($this->sut()->getMetadata(), JSON_THROW_ON_ERROR),
            true,
            512,
            JSON_THROW_ON_ERROR,
        );

        $this->assertSame([ClaimsEnum::Jwks->value], array_keys($decoded));
        $this->assertSame([ClaimsEnum::Keys->value], array_keys($decoded[ClaimsEnum::Jwks->value]));

        return $decoded[ClaimsEnum::Jwks->value][ClaimsEnum::Keys->value];
    }


    /**
     * A verifier which has resolved this entity's Trust Chain checks that the credential's `kid` header
     * names a key in this set, and what that header carries depends on the identity mode the credential
     * was issued under. So each key is published under every name a credential may carry for it - the
     * one in use today first, then one per other mode in the modes' own order: the did:jwk URL, which
     * any deployment could have issued under, the did:web URL for as long as one is configured, and the
     * bare id - with everything else about the key as it is. Every configured pair, in the bag's order:
     * a credential signed under a pair since rotated out of the signing seat has to stay verifiable for
     * as long as it is valid.
     *
     * @param list<string> $expectedKeyIdPatterns With `{kid}` standing for the pair's own key id.
     * @throws \JsonException
     */
    #[DataProvider('identityProvider')]
    public function testPublishesEveryCredentialSigningKeyUnderEveryNameACredentialMayCarryForIt(
        VciIssuerIdentifierModeEnum $mode,
        ?string $didWeb,
        array $expectedKeyIdPatterns,
    ): void {
        $this->issuerIdentifier = new VciIssuerIdentifier($mode, $didWeb);

        $keys = $this->publishedKeys();

        $expected = [];
        foreach (['vci-01', 'vci-02'] as $keyId) {
            foreach ($expectedKeyIdPatterns as $pattern) {
                $expectedJwk = self::PUBLIC_JWKS[$keyId];
                $expectedJwk[ClaimsEnum::Kid->value] = str_replace('{kid}', $keyId, $pattern);
                ksort($expectedJwk);
                $expected[] = $expectedJwk;
            }
        }

        // Same members, whatever order serialisation put them in.
        $published = array_map(
            static function (array $jwk): array {
                ksort($jwk);

                return $jwk;
            },
            $keys,
        );

        $this->assertSame($expected, $published);
    }


    /**
     * @return array<string,array{
     *     0: \SimpleSAML\Module\oidc\Codebooks\VciIssuerIdentifierModeEnum,
     *     1: ?string,
     *     2: list<string>,
     * }>
     */
    public static function identityProvider(): array
    {
        return [
            'did:jwk, nothing else ever configured' => [
                VciIssuerIdentifierModeEnum::DidJwk,
                null,
                ['did:jwk:{kid}#0', '{kid}'],
            ],
            'did:jwk, with the did:web it issued under before still configured' => [
                VciIssuerIdentifierModeEnum::DidJwk,
                self::DID_WEB,
                ['did:jwk:{kid}#0', self::DID_WEB . '#{kid}', '{kid}'],
            ],
            'did:web' => [
                VciIssuerIdentifierModeEnum::DidWeb,
                self::DID_WEB,
                [self::DID_WEB . '#{kid}', 'did:jwk:{kid}#0', '{kid}'],
            ],
            'https, nothing else ever configured' => [
                VciIssuerIdentifierModeEnum::Https,
                null,
                ['{kid}', 'did:jwk:{kid}#0'],
            ],
            'https, with a did:web still configured' => [
                VciIssuerIdentifierModeEnum::Https,
                self::DID_WEB,
                ['{kid}', 'did:jwk:{kid}#0', self::DID_WEB . '#{kid}'],
            ],
        ];
    }


    /**
     * The name in use today is asked of the resolver which names the key at signing time, for each
     * pair under the identity this deployment is configured to issue under - the same identifier
     * object configuration handed out, not one rebuilt here - so that what a credential carries and
     * what this publishes can not be built under different rules.
     *
     * @throws \JsonException
     */
    public function testAsksTheSigningTimeResolverForEachPairUnderTheConfiguredIdentity(): void
    {
        $this->issuerIdentifier = new VciIssuerIdentifier(VciIssuerIdentifierModeEnum::DidWeb, self::DID_WEB);

        $this->publishedKeys();

        $askedUnderTheConfiguredIdentity = array_values(array_filter(
            $this->resolutions,
            fn(array $resolution): bool => $resolution['identifier'] === $this->issuerIdentifier,
        ));

        $this->assertSame(['vci-01', 'vci-02'], array_column($askedUnderTheConfiguredIdentity, 'keyId'));
    }


    /**
     * Each name is resolved once. The name in use today is not resolved a second time as the alias for
     * its own mode, and a did:web is not resolved at all where none is configured.
     *
     * @throws \JsonException
     */
    public function testResolvesEachNameOnce(): void
    {
        $this->issuerIdentifier = new VciIssuerIdentifier(VciIssuerIdentifierModeEnum::DidJwk);

        $this->publishedKeys();

        // Two pairs, each under the configured did:jwk identity only: the https alias needs no
        // resolving and there is no did:web to name.
        $this->assertCount(2, $this->resolutions);
        foreach ($this->resolutions as $resolution) {
            $this->assertSame($this->issuerIdentifier, $resolution['identifier']);
        }
    }


    /**
     * With a did:web configured beside the did:jwk in use, once more per pair for it - and still not
     * twice for did:jwk.
     *
     * @throws \JsonException
     */
    public function testResolvesARetainedDidWebOncePerPair(): void
    {
        $this->issuerIdentifier = new VciIssuerIdentifier(VciIssuerIdentifierModeEnum::DidJwk, self::DID_WEB);

        $this->publishedKeys();

        $this->assertSame(
            [
                VciIssuerIdentifierModeEnum::DidJwk, VciIssuerIdentifierModeEnum::DidWeb,
                VciIssuerIdentifierModeEnum::DidJwk, VciIssuerIdentifierModeEnum::DidWeb,
            ],
            array_map(
                static fn(array $resolution): VciIssuerIdentifierModeEnum => $resolution['identifier']->getMode(),
                $this->resolutions,
            ),
        );
    }


    /**
     * An alias the resolver refuses to derive - a key too large to fit in a did:jwk, say - names no
     * credential, since it could not have been derived when one was issued either. So it is left out,
     * and the key is still published under the names that could be derived.
     *
     * @throws \JsonException
     */
    public function testAnAliasTheResolverCanNotDeriveIsLeftOutRatherThanFailingThePublication(): void
    {
        $this->issuerIdentifier = new VciIssuerIdentifier(VciIssuerIdentifierModeEnum::Https, self::DID_WEB);

        $this->vciIssuerIdentityResolverMock = $this->createMock(VciIssuerIdentityResolver::class);
        $this->vciIssuerIdentityResolverMock->method('resolve')->willReturnCallback(
            static function (VciIssuerIdentifier $identifier, SignatureKeyPair $pair): VciIssuerIdentity {
                $keyId = $pair->getKeyPair()->getKeyId();

                return match ($identifier->getMode()) {
                    VciIssuerIdentifierModeEnum::Https => new VciIssuerIdentity(
                        VciIssuerIdentifierModeEnum::Https,
                        'https://issuer.com',
                        $keyId,
                    ),
                    VciIssuerIdentifierModeEnum::DidJwk => throw new OidcException(
                        'Unable to derive the did:jwk identifier for the signing key: too large.',
                    ),
                    VciIssuerIdentifierModeEnum::DidWeb => new VciIssuerIdentity(
                        VciIssuerIdentifierModeEnum::DidWeb,
                        self::DID_WEB,
                        self::DID_WEB . '#' . $keyId,
                    ),
                };
            },
        );

        $this->assertSame(
            ['vci-01', self::DID_WEB . '#vci-01', 'vci-02', self::DID_WEB . '#vci-02'],
            array_column($this->publishedKeys(), ClaimsEnum::Kid->value),
        );
    }


    /**
     * Only the resolver's own refusal is read as "no such name". Anything else thrown while deriving
     * an alias is a fault - a mode nobody taught the service to name, an engine error - and is not
     * published around, or the fault would show up only as a key quietly missing a name.
     */
    public function testAnyOtherFailureWhileDerivingAnAliasIsAFaultAndEscapes(): void
    {
        $this->issuerIdentifier = new VciIssuerIdentifier(VciIssuerIdentifierModeEnum::Https);

        $this->vciIssuerIdentityResolverMock = $this->createMock(VciIssuerIdentityResolver::class);
        $this->vciIssuerIdentityResolverMock->method('resolve')->willReturnCallback(
            static function (VciIssuerIdentifier $identifier, SignatureKeyPair $pair): VciIssuerIdentity {
                if ($identifier->getMode() === VciIssuerIdentifierModeEnum::DidJwk) {
                    throw new RuntimeException('Not a refusal to name the key.');
                }

                return new VciIssuerIdentity(
                    VciIssuerIdentifierModeEnum::Https,
                    'https://issuer.com',
                    $pair->getKeyPair()->getKeyId(),
                );
            },
        );

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Not a refusal to name the key.');

        $this->sut()->getMetadata();
    }


    /**
     * The name in use today is another matter: a resolver which can not name a key under the configured
     * identity is a deployment whose credential issuance is misconfigured, and that is for the caller
     * to contain and report - not something to publish around.
     */
    public function testAFailureToNameTheKeyUnderTheConfiguredIdentityIsTheCallersToHandle(): void
    {
        $this->vciIssuerIdentityResolverMock = $this->createMock(VciIssuerIdentityResolver::class);
        $this->vciIssuerIdentityResolverMock->method('resolve')
            ->willThrowException(new OidcException('Unable to derive the did:jwk identifier.'));

        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('Unable to derive the did:jwk identifier.');

        $this->sut()->getMetadata();
    }


    /**
     * These are verification keys, and what they verify outlives the switch which stops new credentials
     * being issued, so the switch is not consulted: the keys are published wherever they can be built,
     * and a deployment which turns issuance off retains them by keeping them configured.
     *
     * @throws \JsonException
     */
    public function testDoesNotConsultTheIssuanceSwitch(): void
    {
        $this->moduleConfigMock->expects($this->never())->method('getVciEnabled');

        $this->assertCount(4, $this->publishedKeys());
    }


    /**
     * And a deployment with no credential keys configured has nothing to publish, which it says the way
     * configuration says it - so the caller can tell that apart from a set it could build.
     */
    public function testADeploymentWithoutCredentialKeysHasNothingToPublish(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getVciIssuerIdentifier')->willReturn($this->issuerIdentifier);
        $this->moduleConfigMock->method('getVciSignatureKeyPairBag')->willThrowException(
            new ConfigurationError('At least one VCI signature key-pair pair must be provided.'),
        );

        $this->expectException(ConfigurationError::class);

        $this->sut()->getMetadata();
    }


    /**
     * The Entity Configuration is wired to this service whether or not the deployment has credential
     * keys at all, and finds out by asking for the document. That holds only while constructing the
     * service reads nothing.
     */
    public function testConstructingItReadsNoConfiguration(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->expects($this->never())->method($this->anything());
        $this->jwkMock = $this->createMock(Jwk::class);
        $this->jwkMock->expects($this->never())->method($this->anything());
        $this->jwksMock = $this->createMock(Jwks::class);
        $this->jwksMock->expects($this->never())->method($this->anything());
        $this->vciIssuerIdentityResolverMock = $this->createMock(VciIssuerIdentityResolver::class);
        $this->vciIssuerIdentityResolverMock->expects($this->never())->method($this->anything());

        $this->sut();
    }


    /**
     * Asked twice, it hands back the same set rather than resolving every name again. Arrays compare
     * by value, so the second call is shown to have built nothing by the resolutions it did not make.
     */
    public function testBuildsTheDocumentOnce(): void
    {
        $sut = $this->sut();

        $this->assertSame($sut->getMetadata(), $sut->getMetadata());

        // Two pairs, each named under the configured did:jwk identity: two resolutions, not four.
        $this->assertCount(2, $this->resolutions);
    }
}
