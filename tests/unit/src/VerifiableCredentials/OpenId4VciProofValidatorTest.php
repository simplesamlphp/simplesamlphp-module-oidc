<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\VerifiableCredentials;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum;
use SimpleSAML\Module\oidc\Codebooks\VciCredentialBindingPolicyEnum;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Exceptions\CredentialRequestException;
use SimpleSAML\Module\oidc\Factories\DidFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Services\NonceService;
use SimpleSAML\Module\oidc\VerifiableCredentials\OpenId4VciProofValidator;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmBag;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\VerificationRelationshipEnum;
use SimpleSAML\OpenID\Did;
use SimpleSAML\OpenID\Did\DidDocument;
use SimpleSAML\OpenID\Did\DidJwkResolver;
use SimpleSAML\OpenID\Did\DidUrl;
use SimpleSAML\OpenID\Did\ResolvedVerificationMethod;
use SimpleSAML\OpenID\Exceptions\DidException;
use SimpleSAML\OpenID\Exceptions\JwsException;
use SimpleSAML\OpenID\SupportedAlgorithms;
use SimpleSAML\OpenID\VerifiableCredentials as VerifiableCredentialsService;
use SimpleSAML\OpenID\VerifiableCredentials\Factories\OpenId4VciProofFactory;
use SimpleSAML\OpenID\VerifiableCredentials\OpenId4VciProof;

/**
 * What a key proof has to satisfy before a credential is issued against it.
 *
 * Each of these used to pass. A proof naming a key this issuer could not resolve, one carrying no nonce,
 * one addressed to somewhere else as well as here, or no proof at all, all ended in a credential being
 * issued - the last three bound to a subject identifier this issuer made up, with a warning in the log
 * as the only sign. A wallet could not tell any of that apart from a proof which had been honoured.
 */
#[CoversClass(OpenId4VciProofValidator::class)]
#[AllowMockObjectsWithoutExpectations]
class OpenId4VciProofValidatorTest extends TestCase
{
    protected const string ISSUER = 'https://issuer.com';

    protected const string CLIENT_ID = 'https://wallet.example.org';

    protected const string HOLDER_DID = 'did:jwk:eyJrdHkiOiJFQyJ9';

    protected const string HOLDER_DID_URL = self::HOLDER_DID . '#0';

    protected const string HOLDER_DID_WEB = 'did:web:wallet.example.org';

    protected const string HOLDER_DID_WEB_URL = self::HOLDER_DID_WEB . '#key-1';

    /** @var array<string,string> A public EC key, as a wallet would send it in a `jwk` header. */
    protected const array PUBLIC_EC_JWK = [
        'kty' => 'EC',
        'crv' => 'P-256',
        'x' => 'x-value',
        'y' => 'y-value',
    ];


    protected MockObject $moduleConfigMock;

    protected MockObject $verifiableCredentialsMock;

    protected MockObject $didMock;

    protected MockObject $nonceServiceMock;

    protected MockObject $loggerServiceMock;

    protected MockObject $proofFactoryMock;

    protected MockObject $didJwkResolverMock;

    protected MockObject $accessTokenMock;

    /** How many times the request under test sent this issuer out to resolve a DID document. */
    protected int $documentResolutions = 0;


    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->verifiableCredentialsMock = $this->createMock(VerifiableCredentialsService::class);
        $this->didJwkResolverMock = $this->createMock(DidJwkResolver::class);
        $this->didMock = $this->freshDidMock();
        $this->nonceServiceMock = $this->createMock(NonceService::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);

        $this->moduleConfigMock->method('getIssuer')->willReturn(self::ISSUER);
        // One advertised algorithm, so a proof signed with any other is unadvertised rather than merely
        // unusual.
        $this->moduleConfigMock->method('getSupportedAlgorithms')->willReturn(
            new SupportedAlgorithms(new SignatureAlgorithmBag(SignatureAlgorithmEnum::ES256)),
        );

        $this->proofFactoryMock = $this->createMock(OpenId4VciProofFactory::class);
        $this->verifiableCredentialsMock->method('openId4VciProofFactory')->willReturn($this->proofFactoryMock);

        $this->didJwkResolverMock->method('generateDidJwkFromJwk')->willReturn(self::HOLDER_DID);

        // One call handles every DID method, so the resolvers behind it are no longer stubbed one by
        // one. Whichever verification method a proof names resolves to a key under the DID it sits
        // under, which is what lets a test spoil that relationship on purpose.
        $this->documentResolutions = 0;
        $this->didMock->method('resolveDocument')->willReturnCallback(
            function (string $did): DidDocument {
                $this->documentResolutions++;

                return $this->didDocument($did);
            },
        );

        $this->nonceServiceMock->method('validateNonce')->willReturn(true);

        // An authenticated wallet by default, so the anonymous pre-authorized rules are opted into by
        // the tests which are about them rather than applying everywhere.
        $this->walletIdentifiedAs(self::CLIENT_ID);
    }


    /**
     * The access token a proof accompanies, issued to a wallet known by this identifier.
     */
    protected function walletIdentifiedAs(string $clientId): void
    {
        $clientMock = $this->createMock(ClientEntityInterface::class);
        $clientMock->method('getIdentifier')->willReturn($clientId);
        $this->accessTokenMock = $this->createMock(AccessTokenEntity::class);
        $this->accessTokenMock->method('getFlowTypeEnum')->willReturn(FlowTypeEnum::VciAuthorizationCode);
        $this->accessTokenMock->method('getBoundClientId')->willReturn(null);
        $this->accessTokenMock->method('getClient')->willReturn($clientMock);
    }


    /**
     * A document which offers every key asked of it, under the authentication relationship.
     *
     * Documents rather than single methods, because that is what the validator resolves: one fetch
     * answers for every key of one holder, and a test can count the fetches a request caused.
     */
    protected function didDocument(string $did): DidDocument
    {
        $didDocumentMock = $this->createMock(DidDocument::class);
        $didDocumentMock->method('getId')->willReturn($did);
        // A named method rather than a closure: rector rewrites a single-return closure into an arrow
        // function, and the arrow function this one becomes is too long for the line limit phpcs
        // enforces, so the two tools disagree about every spelling but this one.
        $didDocumentMock->method('resolveVerificationMethod')->willReturnCallback(
            $this->verificationMethodIn(...),
        );

        return $didDocumentMock;
    }


    protected function verificationMethodIn(
        DidUrl $didUrl,
        ?VerificationRelationshipEnum $relationship,
    ): ResolvedVerificationMethod {
        return new ResolvedVerificationMethod(
            $didUrl->getDid(),
            $didUrl,
            self::PUBLIC_EC_JWK,
            $relationship,
        );
    }


    protected function resolvedVerificationMethod(string $didUrl): ResolvedVerificationMethod
    {
        $parsedDidUrl = new DidUrl($didUrl);

        return new ResolvedVerificationMethod(
            $parsedDidUrl->getDid(),
            $parsedDidUrl,
            self::PUBLIC_EC_JWK,
            VerificationRelationshipEnum::Authentication,
        );
    }


    /**
     * Constructing this validator builds no DID facade.
     *
     * It is a constructor argument of the Credential Endpoint controller, so the container builds it
     * before that controller's own constructor body can refuse a deployment with Verifiable Credentials
     * switched off. Holding a built facade here therefore made the DID and cache settings decide the
     * answer to a request that endpoint refuses outright.
     */
    public function testBuildsNoDidFacadeUntilAProofNeedsOne(): void
    {
        $didFactoryMock = $this->createMock(DidFactory::class);
        $didFactoryMock->expects($this->never())->method('build');

        $validator = new OpenId4VciProofValidator(
            $this->moduleConfigMock,
            $this->verifiableCredentialsMock,
            $didFactoryMock,
            $this->nonceServiceMock,
            $this->loggerServiceMock,
        );

        // Nor does a configuration which validates no proof at all, though it goes the whole way
        // through a request.
        $validator->validateRequest(
            ['credential_configuration_id' => 'test'],
            VciCredentialBindingPolicyEnum::Proofless,
            $this->accessTokenMock,
        );
    }


    protected function sut(): OpenId4VciProofValidator
    {
        $didFactoryMock = $this->createMock(DidFactory::class);
        // Resolved when the validator asks rather than when this is wired up, since a test which
        // replaces the facade mock to steer one call does so before reaching for the subject.
        $didFactoryMock->method('build')->willReturnCallback(fn(): Did => $this->didMock);

        return new OpenId4VciProofValidator(
            $this->moduleConfigMock,
            $this->verifiableCredentialsMock,
            $didFactoryMock,
            $this->nonceServiceMock,
            $this->loggerServiceMock,
        );
    }


    /**
     * A key proof which passes everything, so that each test can spoil exactly one thing about it.
     *
     * @param array<string,mixed> $overrides
     */
    protected function proofMock(array $overrides = []): MockObject
    {
        $claims = array_merge(
            [
                'getAlgorithm' => SignatureAlgorithmEnum::ES256->value,
                'getIssuer' => self::CLIENT_ID,
                'getKeyId' => self::HOLDER_DID_URL,
                'getJsonWebKey' => null,
                'getX509CertificateChain' => null,
                'getNonce' => 'nonce-value',
            ],
            $overrides,
        );

        // The audience is read off the raw payload claim rather than through getAudience(), because its
        // original type is what decides whether the proof is addressed to this issuer alone.
        /** @var mixed $audience */
        $audience = array_key_exists('aud', $claims) ? $claims['aud'] : self::ISSUER;
        unset($claims['aud']);

        $proofMock = $this->createMock(OpenId4VciProof::class);
        $proofMock->method('getPayloadClaim')->willReturnCallback(
            /** @return mixed */
            static fn(string $key): mixed => $key === ClaimsEnum::Aud->value ? $audience : null,
        );

        /** @var mixed $value */
        foreach ($claims as $method => $value) {
            $proofMock->method($method)->willReturn($value);
        }

        return $proofMock;
    }


    /**
     * A `Did` mock carrying the stubs every test needs, whatever else it goes on to control.
     *
     * The registry among them: the binding policy is filtered against it before any resolution is
     * attempted, so a test replacing this mock to steer one call and rebuilding it by hand would have
     * its proof refused for naming an unaccepted method - and a test which expected a refusal anyway
     * would keep passing while no longer exercising what it was written for.
     */
    protected function freshDidMock(): MockObject
    {
        $didMock = $this->createMock(Did::class);
        $didMock->method('supportedMethods')->willReturn(['did:jwk', 'did:key', 'did:web']);
        $didMock->method('didJwkResolver')->willReturn($this->didJwkResolverMock);

        return $didMock;
    }


    /**
     * @param array<string,mixed> $overrides
     * @return array<string,mixed>
     */
    protected function requestWith(array $overrides = [], int $proofCount = 1): array
    {
        $this->proofFactoryMock->method('fromToken')->willReturnCallback(
            fn(): OpenId4VciProof => $this->proofMock($overrides),
        );

        return ['proofs' => ['jwt' => array_fill(0, $proofCount, 'proof-jwt')]];
    }


    /**
     * A request whose proofs differ from one another, for the rules which are about the request rather
     * than about any one proof in it.
     *
     * @param list<array<string,mixed>> $overridesPerProof
     * @return array<string,mixed>
     */
    protected function requestWithProofs(array $overridesPerProof): array
    {
        $index = 0;
        $this->proofFactoryMock->method('fromToken')->willReturnCallback(
            function () use ($overridesPerProof, &$index): OpenId4VciProof {
                /** @var array<string,mixed> $overrides */
                $overrides = $overridesPerProof[$index++] ?? [];

                return $this->proofMock($overrides);
            },
        );

        return ['proofs' => ['jwt' => array_fill(0, count($overridesPerProof), 'proof-jwt')]];
    }


    /**
     * @param array<array-key,mixed> $requestData
     */
    protected function assertRefusedWith(
        string $expectedErrorCode,
        array $requestData,
        VciCredentialBindingPolicyEnum $bindingPolicy = VciCredentialBindingPolicyEnum::ProofBound,
        ?string $expectedMessageFragment = null,
    ): void {
        try {
            $this->sut()->validateRequest($requestData, $bindingPolicy, $this->accessTokenMock);
        } catch (CredentialRequestException $credentialRequestException) {
            $this->assertSame($expectedErrorCode, $credentialRequestException->getErrorCode());

            if (is_string($expectedMessageFragment)) {
                $this->assertStringContainsString(
                    $expectedMessageFragment,
                    $credentialRequestException->getMessage(),
                );
            }

            return;
        }

        $this->fail(sprintf('The request was not refused, and "%s" was expected.', $expectedErrorCode));
    }


    /*****************************************************************************************************
     * Whether a proof is required at all.
     ****************************************************************************************************/

    /**
     * @throws \Throwable
     */
    public function testAcceptsAValidProof(): void
    {
        $validatedProofs = $this->sut()->validateRequest(
            $this->requestWith(),
            VciCredentialBindingPolicyEnum::ProofBound,
            $this->accessTokenMock,
        );

        $this->assertCount(1, $validatedProofs);
        $this->assertNotNull($validatedProofs[0]);
        $this->assertSame(self::HOLDER_DID, $validatedProofs[0]->getSubject());
        // The verification method the wallet named, so the credential's `cnf` claim can carry it.
        $this->assertSame(self::HOLDER_DID_URL, $validatedProofs[0]->getKeyId());
    }


    /**
     * The metadata this configuration publishes says a key proof is required, so issuing without one
     * would be handing out a credential bound to nothing while claiming otherwise.
     */
    public function testRefusesAProofBoundRequestWhichCarriesNoProof(): void
    {
        $this->assertRefusedWith('invalid_proof', []);
    }


    /**
     * The pre-final singular parameter is not the shape a configuration advertising the final
     * `proof_types_supported` describes.
     */
    public function testRefusesTheSingularProofParameter(): void
    {
        $this->assertRefusedWith('invalid_proof', ['proof' => ['proof_type' => 'jwt', 'jwt' => 'proof-jwt']]);
    }


    /**
     * @throws \Throwable
     */
    public function testAProoflessConfigurationNeedsNoProof(): void
    {
        $validatedProofs = $this->sut()->validateRequest(
            [],
            VciCredentialBindingPolicyEnum::Proofless,
            $this->accessTokenMock,
        );

        // One credential, bound to nothing, which is what the caller reads a null entry as.
        $this->assertSame([null], $validatedProofs);
    }


    /**
     * Nothing told this wallet which proof type or signing algorithm to build a proof with, so honouring
     * one it sent anyway would mean accepting a proof under rules that were never published. Ignoring it
     * silently is worse still: the wallet would get back a credential bound to something else, with
     * nothing on it to say its key went unused.
     */
    public function testAProoflessConfigurationRefusesASuppliedProof(): void
    {
        $this->assertRefusedWith(
            'invalid_credential_request',
            ['proofs' => ['jwt' => ['proof-jwt']]],
            VciCredentialBindingPolicyEnum::Proofless,
        );

        $this->assertRefusedWith(
            'invalid_credential_request',
            ['proof' => ['proof_type' => 'jwt', 'jwt' => 'proof-jwt']],
            VciCredentialBindingPolicyEnum::Proofless,
        );
    }


    /*****************************************************************************************************
     * The shape of the `proofs` envelope, which used to be flattened before it was looked at.
     ****************************************************************************************************/

    public function testRefusesAnEnvelopeNamingMoreThanOneProofType(): void
    {
        $this->assertRefusedWith('invalid_proof', ['proofs' => ['jwt' => ['a'], 'ldp_vp' => ['b']]]);
    }


    public function testRefusesAnUnsupportedProofType(): void
    {
        $this->assertRefusedWith('invalid_proof', ['proofs' => ['ldp_vp' => ['a']]]);
    }


    public function testRefusesAnEnvelopeWhoseProofsAreNotANonEmptyList(): void
    {
        $this->assertRefusedWith('invalid_proof', ['proofs' => ['jwt' => []]]);
        $this->assertRefusedWith('invalid_proof', ['proofs' => ['jwt' => 'proof-jwt']]);
        $this->assertRefusedWith('invalid_proof', ['proofs' => ['jwt' => ['first' => 'proof-jwt']]]);
    }


    /**
     * A malformed entry used to be skipped, so a request could quietly be issued fewer credentials than
     * it asked for.
     */
    public function testRefusesAnEnvelopeCarryingAMalformedProof(): void
    {
        $this->assertRefusedWith('invalid_proof', ['proofs' => ['jwt' => ['proof-jwt', 42]]]);
        $this->assertRefusedWith('invalid_proof', ['proofs' => ['jwt' => ['proof-jwt', '']]]);
    }


    /**
     * Every proof issues a credential and claims a Status List entry of its own, so an uncapped array
     * lets one authenticated request spend an arbitrary amount of storage and signing work.
     *
     * @throws \Throwable
     */
    public function testRefusesMoreProofsThanTheAdvertisedBatchSize(): void
    {
        $atTheLimit = $this->sut()->validateRequest(
            $this->requestWith(proofCount: ModuleConfig::VCI_BATCH_SIZE),
            VciCredentialBindingPolicyEnum::ProofBound,
            $this->accessTokenMock,
        );
        $this->assertCount(ModuleConfig::VCI_BATCH_SIZE, $atTheLimit);

        $this->setUp();
        $this->assertRefusedWith(
            'invalid_proof',
            ['proofs' => ['jwt' => array_fill(0, ModuleConfig::VCI_BATCH_SIZE + 1, 'proof-jwt')]],
        );
    }


    /*****************************************************************************************************
     * The JOSE header, whose shape used to be unconstrained.
     ****************************************************************************************************/

    public function testRefusesAHeaderNamingNoKeySource(): void
    {
        $this->assertRefusedWith('invalid_proof', $this->requestWith(['getKeyId' => null]));
    }


    public function testRefusesAHeaderNamingMoreThanOneKeySource(): void
    {
        $this->assertRefusedWith('invalid_proof', $this->requestWith(['getJsonWebKey' => self::PUBLIC_EC_JWK]));
    }


    /**
     * Accepted by the parser and ignored by this module, which meant a proof presented as certificate
     * bound was verified against something else entirely.
     */
    public function testRefusesACertificateChainHeader(): void
    {
        $this->assertRefusedWith(
            'invalid_proof',
            $this->requestWith(['getKeyId' => null, 'getX509CertificateChain' => ['cert']]),
        );
    }


    /**
     * @throws \Throwable
     */
    public function testAcceptsAProofCarryingItsPublicKeyInline(): void
    {
        $validatedProofs = $this->sut()->validateRequest(
            $this->requestWith(['getKeyId' => null, 'getJsonWebKey' => self::PUBLIC_EC_JWK]),
            VciCredentialBindingPolicyEnum::ProofBound,
            $this->accessTokenMock,
        );

        $this->assertNotNull($validatedProofs[0]);
        $this->assertSame(self::HOLDER_DID, $validatedProofs[0]->getSubject());
        // No verification method was named, so there is none to carry into the credential.
        $this->assertNull($validatedProofs[0]->getKeyId());
    }


    /**
     * A `jwk` header goes straight into the `did:jwk` this module synthesises for the credential's
     * subject, so a private member left in one would be published inside the credential the wallet
     * itself asked for.
     *
     * The members are refused by allowing only what a public key of that type is made of, so this holds
     * for a member nobody thought to list, not just for the ones named here.
     */
    public function testRefusesPrivateKeyMaterialInAnInlineKey(): void
    {
        foreach (['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k', 'invented_member'] as $privateMember) {
            $this->setUp();

            $this->assertRefusedWith(
                'invalid_proof',
                $this->requestWith([
                    'getKeyId' => null,
                    'getJsonWebKey' => array_merge(self::PUBLIC_EC_JWK, [$privateMember => 'secret']),
                ]),
            );
        }
    }


    /**
     * A shared secret proves possession to nobody, so it is not something a key proof can be built on.
     */
    public function testRefusesASymmetricInlineKey(): void
    {
        $this->assertRefusedWith(
            'invalid_proof',
            $this->requestWith(['getKeyId' => null, 'getJsonWebKey' => ['kty' => 'oct']]),
        );
    }


    /**
     * A wallet was told which algorithms this issuer accepts for key proofs, so verifying under one it
     * was never told about applies rules nobody published.
     */
    public function testRefusesAnUnadvertisedSigningAlgorithm(): void
    {
        $this->assertRefusedWith(
            'invalid_proof',
            $this->requestWith(['getAlgorithm' => SignatureAlgorithmEnum::RS256->value]),
        );
    }


    /**
     * A `kid` which is not a DID URL at all is refused rather than falling through, which is what left
     * proofs unverified before every method went through one resolution call.
     */
    public function testRefusesAVerificationMethodItCanNotResolve(): void
    {
        $this->assertRefusedWith('invalid_proof', $this->requestWith(['getKeyId' => 'not-a-did']));
    }


    /**
     * A JOSE `kid` names a key. Resolving the bare DID and then picking a verification method out of
     * its document would be this issuer choosing which of the holder's keys the credential is bound to,
     * and writing that choice into a `cnf` claim the wallet never asserted.
     */
    public function testRefusesAKeyIdWhichNamesOnlyTheDid(): void
    {
        $this->assertRefusedWith('invalid_proof', $this->requestWith(['getKeyId' => self::HOLDER_DID]));
        $this->assertRefusedWith('invalid_proof', $this->requestWith(['getKeyId' => self::HOLDER_DID_WEB]));
    }


    public function testRefusesADidWhichFailsToResolve(): void
    {
        $this->didMock = $this->freshDidMock();
        $this->didMock->method('resolveDocument')
            ->willThrowException(new DidException('could not be retrieved'));

        $this->assertRefusedWith('invalid_proof', $this->requestWith());
    }


    /**
     * A document which resolves but does not offer the named key for authentication is refused just the
     * same, and with the same message: which of the two failed is a wallet's own business to work out.
     *
     * Note the policy here is the default `ProofBound`, not `DiipProofBound`. A verification
     * relationship is how a DID controller says what a key may be used for, so a key listed under none
     * of them has not been authorized to authenticate with, whichever profile the configuration runs.
     */
    public function testRefusesAVerificationMethodTheDocumentDoesNotOffer(): void
    {
        $didDocumentMock = $this->createMock(DidDocument::class);
        $didDocumentMock->method('resolveVerificationMethod')
            ->willThrowException(new DidException('not under that relationship'));

        $this->didMock = $this->freshDidMock();
        $this->didMock->method('resolveDocument')->willReturn($didDocumentMock);

        $this->assertRefusedWith('invalid_proof', $this->requestWith());
    }


    /**
     * The holder authenticates with this key, so the document has to list it under that relationship.
     * Passing none would search the document's own verificationMethod entries instead, which is not the
     * same question.
     */
    public function testResolvesUnderTheAuthenticationRelationship(): void
    {
        $didDocumentMock = $this->createMock(DidDocument::class);
        $didDocumentMock->expects($this->once())->method('resolveVerificationMethod')
            ->with(
                $this->callback(
                    static fn(DidUrl $didUrl): bool => $didUrl->getValue() === self::HOLDER_DID_URL,
                ),
                VerificationRelationshipEnum::Authentication,
            )
            ->willReturn($this->resolvedVerificationMethod(self::HOLDER_DID_URL));

        $this->didMock = $this->freshDidMock();
        // The whole request shares one deadline, so the fetch is bounded by when the request has to be
        // done rather than by the per-fetch timeout each proof would otherwise get to itself.
        $this->didMock->expects($this->once())->method('resolveDocument')
            ->with(self::HOLDER_DID, $this->isFloat())
            ->willReturn($didDocumentMock);

        $this->sut()->validateRequest(
            $this->requestWith(),
            VciCredentialBindingPolicyEnum::ProofBound,
            $this->accessTokenMock,
        );
    }


    /**
     * `did:web` is the point of this step: it resolves through the same call as every other method,
     * rather than needing a branch of its own added to a chain.
     */
    public function testAcceptsADidWebHolder(): void
    {
        $validatedProofs = $this->sut()->validateRequest(
            $this->requestWith(['getKeyId' => self::HOLDER_DID_WEB_URL]),
            VciCredentialBindingPolicyEnum::ProofBound,
            $this->accessTokenMock,
        );

        $this->assertNotNull($validatedProofs[0]);
        $this->assertSame(self::HOLDER_DID_WEB, $validatedProofs[0]->getSubject());
        $this->assertSame(self::HOLDER_DID_WEB_URL, $validatedProofs[0]->getKeyId());
    }


    /*****************************************************************************************************
     * What one request may spend on resolving the DIDs it names.
     ****************************************************************************************************/

    /**
     * A DID which has to be fetched is fetched once, however many proofs in the request name it.
     */
    public function testResolvesADidOnlyOncePerRequest(): void
    {
        $this->sut()->validateRequest(
            $this->requestWithProofs(array_fill(0, 4, ['getKeyId' => self::HOLDER_DID_WEB_URL])),
            VciCredentialBindingPolicyEnum::ProofBound,
            $this->accessTokenMock,
        );

        $this->assertSame(1, $this->documentResolutions);
    }


    /**
     * And once for the whole document, not once per key named in it.
     *
     * Memoising the verification method instead would have kept the cap counting DIDs while the
     * requests went out per proof: a batch naming eight keys of one holder is one DID to the budget and
     * was eight fetches on the wire, so the bound this states would have been true about DIDs and false
     * about outbound requests. The library's cache closes the same gap when one is configured; nothing
     * requires one to be.
     */
    public function testResolvesOneDocumentForEveryKeyABatchNamesInIt(): void
    {
        $overridesPerProof = [];

        for ($index = 0; $index < ModuleConfig::VCI_BATCH_SIZE; $index++) {
            $overridesPerProof[] = ['getKeyId' => sprintf('%s#key-%d', self::HOLDER_DID_WEB, $index)];
        }

        $this->sut()->validateRequest(
            $this->requestWithProofs($overridesPerProof),
            VciCredentialBindingPolicyEnum::ProofBound,
            $this->accessTokenMock,
        );

        $this->assertSame(1, $this->documentResolutions);
    }


    /**
     * Eight proofs naming eight hosts is not a wallet collecting credentials, it is a request using this
     * issuer to reach eight places.
     */
    public function testRefusesMoreDistinctFetchedDidsThanOneRequestMay(): void
    {
        $overridesPerProof = [];

        for ($index = 0; $index <= OpenId4VciProofValidator::MAX_NETWORK_RESOLVED_DIDS; $index++) {
            $overridesPerProof[] = ['getKeyId' => sprintf('did:web:wallet%d.example.org#key-1', $index)];
        }

        $this->assertRefusedWith('invalid_proof', $this->requestWithProofs($overridesPerProof));
    }


    /**
     * The cap counts only the DIDs which have to be fetched. Under `did:jwk` every key is its own DID,
     * so counting those as well would refuse a legitimate batch of the advertised size.
     */
    public function testLocallyResolvedDidsDoNotCountAgainstTheFetchBudget(): void
    {
        $overridesPerProof = [];

        for ($index = 0; $index < ModuleConfig::VCI_BATCH_SIZE; $index++) {
            $overridesPerProof[] = ['getKeyId' => sprintf('%s%d', self::HOLDER_DID_URL, $index)];
        }

        $validatedProofs = $this->sut()->validateRequest(
            $this->requestWithProofs($overridesPerProof),
            VciCredentialBindingPolicyEnum::ProofBound,
            $this->accessTokenMock,
        );

        $this->assertCount(ModuleConfig::VCI_BATCH_SIZE, $validatedProofs);
    }


    /*****************************************************************************************************
     * The claims.
     ****************************************************************************************************/

    /**
     * A membership test accepts a proof addressed to this issuer and to somewhere else at the same time,
     * which is a proof built for that other place which this issuer merely happens to be named in.
     */
    public function testRefusesAnAudienceWhichNamesAnyoneElseAsWell(): void
    {
        $this->assertRefusedWith(
            'invalid_proof',
            $this->requestWith(['aud' => [self::ISSUER, 'https://somewhere-else.example.org']]),
        );
    }


    public function testRefusesAnAudienceWhichDoesNotNameThisIssuer(): void
    {
        $this->assertRefusedWith('invalid_proof', $this->requestWith(['aud' => 'https://somewhere-else.example.org']));
    }


    /**
     * RFC 7519 lets an audience be written either way, and a one-element array says exactly what the
     * string does. What is refused is a second audience, not the spelling.
     *
     * @throws \Throwable
     */
    public function testAcceptsASingleAudienceWrittenAsAnArray(): void
    {
        $validatedProofs = $this->sut()->validateRequest(
            $this->requestWith(['aud' => [self::ISSUER]]),
            VciCredentialBindingPolicyEnum::ProofBound,
            $this->accessTokenMock,
        );

        $this->assertCount(1, $validatedProofs);
    }


    /**
     * Why the claim is read before the library normalises it: an object is not an audience, but it
     * survives normalisation as a one-element array and would then pass for one.
     */
    public function testRefusesAnAudienceWhichIsNeitherAStringNorAList(): void
    {
        $this->assertRefusedWith('invalid_proof', $this->requestWith(['aud' => ['primary' => self::ISSUER]]));
    }


    public function testRefusesAProofCarryingNoAudience(): void
    {
        $this->assertRefusedWith('invalid_proof', $this->requestWith(['aud' => null]));
    }


    /**
     * OpenID4VCI constrains this claim when it is present rather than requiring it, so refusing a proof
     * without one would refuse a proof the specification permits.
     *
     * @throws \Throwable
     */
    public function testAcceptsAProofWithNoIssuerClaim(): void
    {
        $validatedProofs = $this->sut()->validateRequest(
            $this->requestWith(['getIssuer' => null]),
            VciCredentialBindingPolicyEnum::ProofBound,
            $this->accessTokenMock,
        );

        $this->assertCount(1, $validatedProofs);
    }


    public function testRefusesAnIssuerClaimNamingAnotherClient(): void
    {
        $this->assertRefusedWith(
            'invalid_proof',
            $this->requestWith(['getIssuer' => 'https://another-wallet.example.org']),
        );
    }


    /**
     * A wallet which is not a registered client is still identified, by the `client_id` it sent, and
     * that identifier is kept apart from the client entity - which for those flows is a stand-in shared
     * by every such wallet. Comparing against the entity would refuse every non-registered wallet.
     *
     * @throws \Throwable
     */
    public function testComparesTheIssuerClaimAgainstTheBoundClientId(): void
    {
        $clientMock = $this->createMock(ClientEntityInterface::class);
        $clientMock->method('getIdentifier')->willReturn('generic-vci-client');
        $this->accessTokenMock = $this->createMock(AccessTokenEntity::class);
        $this->accessTokenMock->method('getFlowTypeEnum')->willReturn(FlowTypeEnum::VciPreAuthorizedCode);
        $this->accessTokenMock->method('getBoundClientId')->willReturn(self::CLIENT_ID);
        $this->accessTokenMock->method('getClient')->willReturn($clientMock);

        $validatedProofs = $this->sut()->validateRequest(
            $this->requestWith(),
            VciCredentialBindingPolicyEnum::ProofBound,
            $this->accessTokenMock,
        );

        $this->assertCount(1, $validatedProofs);
    }


    /**
     * A pre-authorized code redeemed without a `client_id` identifies no wallet, so there is nothing an
     * `iss` claim could be checked against and OpenID4VCI has the wallet leave it out.
     */
    public function testRefusesAnIssuerClaimWhenTheAccessTokenIdentifiesNoClient(): void
    {
        $this->accessTokenMock = $this->createMock(AccessTokenEntity::class);
        $this->accessTokenMock->method('getFlowTypeEnum')->willReturn(FlowTypeEnum::VciPreAuthorizedCode);
        $this->accessTokenMock->method('getBoundClientId')->willReturn(null);

        $this->assertRefusedWith('invalid_proof', $this->requestWith());
    }


    /*****************************************************************************************************
     * The signature and the nonce.
     ****************************************************************************************************/

    public function testRefusesAProofWhichCanNotBeParsed(): void
    {
        $this->proofFactoryMock->method('fromToken')->willThrowException(new JwsException('not a JWS'));

        $this->assertRefusedWith('invalid_proof', ['proofs' => ['jwt' => ['proof-jwt']]]);
    }


    public function testRefusesAProofWhoseSignatureDoesNotVerify(): void
    {
        $proofMock = $this->proofMock();
        $proofMock->method('verifyWithKey')->willThrowException(new JwsException('bad signature'));
        $this->proofFactoryMock->method('fromToken')->willReturn($proofMock);

        $this->assertRefusedWith('invalid_proof', ['proofs' => ['jwt' => ['proof-jwt']]]);
    }


    /**
     * This issuer publishes a Nonce Endpoint, which is what makes the nonce mandatory. Without it the
     * proof stays replayable for as long as it remains unexpired.
     */
    public function testRefusesAProofCarryingNoNonce(): void
    {
        $this->assertRefusedWith('invalid_proof', $this->requestWith(['getNonce' => null]));
    }


    /**
     * A nonce which was there and did not hold up gets its own code, so a wallet knows to ask for a
     * fresh one and retry rather than to go looking for a fault in the proof it built.
     */
    public function testAnswersAStaleNonceWithItsOwnErrorCode(): void
    {
        $this->nonceServiceMock = $this->createMock(NonceService::class);
        $this->nonceServiceMock->method('validateNonce')->willReturn(false);

        $this->assertRefusedWith('invalid_nonce', $this->requestWith());
    }


    /**
     * The whole array is validated before the caller issues anything, so a request whose last proof is
     * bad leaves no trace of its first.
     */
    public function testRefusesTheWholeRequestWhenALaterProofIsBad(): void
    {
        $goodProof = $this->proofMock();
        $badProof = $this->proofMock(['getNonce' => null]);
        $this->proofFactoryMock->method('fromToken')->willReturnOnConsecutiveCalls($goodProof, $badProof);

        $this->assertRefusedWith('invalid_proof', ['proofs' => ['jwt' => ['good-jwt', 'bad-jwt']]]);
    }


    /*****************************************************************************************************
     * The DIIP profile rules, which apply on top of the OpenID4VCI ones for configurations set to them.
     ****************************************************************************************************/

    /**
     * A wallet identified by a `did:web`, naming a key under that same DID. Everything the profile asks
     * for, and the shape a conformant wallet sends.
     *
     * @throws \Throwable
     */
    public function testAcceptsAProofWhichMeetsTheDiipRules(): void
    {
        $this->walletIdentifiedAs(self::HOLDER_DID_WEB);

        $validatedProofs = $this->sut()->validateRequest(
            $this->requestWith([
                'getIssuer' => self::HOLDER_DID_WEB,
                'getKeyId' => self::HOLDER_DID_WEB_URL,
            ]),
            VciCredentialBindingPolicyEnum::DiipProofBound,
            $this->accessTokenMock,
        );

        $this->assertNotNull($validatedProofs[0]);
        $this->assertSame(self::HOLDER_DID_WEB, $validatedProofs[0]->getSubject());
        $this->assertSame(self::HOLDER_DID_WEB_URL, $validatedProofs[0]->getKeyId());
    }


    /**
     * A `did:jwk` holder satisfies the profile just as well, so the rules are about the method being one
     * of the two the profile names rather than about the identifier being fetched.
     *
     * @throws \Throwable
     */
    public function testAcceptsADidJwkHolderUnderTheDiipRules(): void
    {
        $this->walletIdentifiedAs(self::HOLDER_DID);

        $validatedProofs = $this->sut()->validateRequest(
            $this->requestWith(['getIssuer' => self::HOLDER_DID]),
            VciCredentialBindingPolicyEnum::DiipProofBound,
            $this->accessTokenMock,
        );

        $this->assertNotNull($validatedProofs[0]);
        $this->assertSame(self::HOLDER_DID, $validatedProofs[0]->getSubject());
    }


    /**
     * The profile's holder binding is carried by the `kid` header, so a proof with no `iss` at all is
     * accepted here exactly as it is everywhere else.
     *
     * The profile's own text asks for the holder's DID in `iss`, which cannot hold at the same time as
     * OpenID4VCI's rule for an anonymous pre-authorized code. FIDEScommunity/DIIP#83 proposes dropping
     * that requirement in favour of the `kid` rule, and this follows the proposal.
     *
     * @throws \Throwable
     */
    public function testTheDiipRulesDoNotRequireAnIssuerClaim(): void
    {
        $validatedProofs = $this->sut()->validateRequest(
            $this->requestWith(['getIssuer' => null, 'getKeyId' => self::HOLDER_DID_WEB_URL]),
            VciCredentialBindingPolicyEnum::DiipProofBound,
            $this->accessTokenMock,
        );

        $this->assertNotNull($validatedProofs[0]);
        $this->assertSame(self::HOLDER_DID_WEB, $validatedProofs[0]->getSubject());
    }


    /**
     * And a wallet identified by a URL is not turned away. Requiring a DID here would have constrained
     * how a wallet registers while adding nothing to holder binding, which rests on possession of a key
     * the holder's DID document lists.
     *
     * @throws \Throwable
     */
    public function testTheDiipRulesDoNotRequireTheWalletToBeIdentifiedByADid(): void
    {
        // The default wallet, identified by a URL, sending a proof which names it correctly.
        $validatedProofs = $this->sut()->validateRequest(
            $this->requestWith(['getIssuer' => self::CLIENT_ID, 'getKeyId' => self::HOLDER_DID_WEB_URL]),
            VciCredentialBindingPolicyEnum::DiipProofBound,
            $this->accessTokenMock,
        );

        $this->assertNotNull($validatedProofs[0]);
        $this->assertSame(self::HOLDER_DID_WEB, $validatedProofs[0]->getSubject());
    }


    /**
     * A DID `iss` is still accepted, since the profile's text asks for one and nothing here refuses it.
     *
     * @throws \Throwable
     */
    public function testTheDiipRulesStillAcceptADidIssuerClaim(): void
    {
        $this->walletIdentifiedAs(self::HOLDER_DID_WEB);

        $validatedProofs = $this->sut()->validateRequest(
            $this->requestWith([
                'getIssuer' => self::HOLDER_DID_WEB,
                'getKeyId' => self::HOLDER_DID_WEB_URL,
            ]),
            VciCredentialBindingPolicyEnum::DiipProofBound,
            $this->accessTokenMock,
        );

        $this->assertNotNull($validatedProofs[0]);
        $this->assertSame(self::HOLDER_DID_WEB, $validatedProofs[0]->getSubject());
    }


    /**
     * `did:key` keeps working for every other configuration. The profile names two methods, and it is
     * the `kid` header they constrain.
     */
    public function testTheDiipRulesRefuseAHolderMethodTheProfileDoesNotName(): void
    {
        $didKey = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';

        $this->assertRefusedWith(
            'invalid_proof',
            $this->requestWith(['getKeyId' => $didKey . '#z6Mkh']),
            VciCredentialBindingPolicyEnum::DiipProofBound,
            // Naming what this configuration does accept, and naming it from the same source the
            // metadata advertises, so a refusal cannot describe a different issuer than the published
            // document does.
            'identified by did:jwk or did:web only',
        );

        // Refused before the fetch, not after. Nothing is fetched for a did:key either way, but the
        // same ordering holds for a method which would be.
        $this->assertSame(0, $this->documentResolutions);
    }


    /**
     * The profile's requirements are written in DID URLs, and a key sent inline names no verification
     * method for one to point at. Every other configuration keeps accepting it.
     */
    public function testTheDiipRulesRefuseAnInlineKey(): void
    {
        $this->walletIdentifiedAs(self::HOLDER_DID_WEB);

        $this->assertRefusedWith(
            'invalid_proof',
            $this->requestWith([
                'getIssuer' => self::HOLDER_DID_WEB,
                'getKeyId' => null,
                'getJsonWebKey' => self::PUBLIC_EC_JWK,
            ]),
            VciCredentialBindingPolicyEnum::DiipProofBound,
        );
    }


    /**
     * The case the whole `iss` question turns on.
     *
     * OpenID4VCI requires the claim to be absent when the access token identifies no client, and the
     * profile's own text requires the holder's DID to be in it. Read literally, the two mean a DIIP
     * configuration could never be issued through an anonymous pre-authorized code. Binding on the
     * `kid` header instead leaves both rules satisfied and the flow usable.
     *
     * @throws \Throwable
     */
    public function testTheDiipRulesAreMetThroughAnAnonymousPreAuthorizedCode(): void
    {
        $this->accessTokenMock = $this->createMock(AccessTokenEntity::class);
        $this->accessTokenMock->method('getFlowTypeEnum')->willReturn(FlowTypeEnum::VciPreAuthorizedCode);
        $this->accessTokenMock->method('getBoundClientId')->willReturn(null);

        $validatedProofs = $this->sut()->validateRequest(
            $this->requestWith(['getIssuer' => null, 'getKeyId' => self::HOLDER_DID_WEB_URL]),
            VciCredentialBindingPolicyEnum::DiipProofBound,
            $this->accessTokenMock,
        );

        $this->assertNotNull($validatedProofs[0]);
        $this->assertSame(self::HOLDER_DID_WEB, $validatedProofs[0]->getSubject());
        $this->assertSame(self::HOLDER_DID_WEB_URL, $validatedProofs[0]->getKeyId());
    }


    /**
     * A pre-authorized code which does identify its wallet is a different case, and the profile applies
     * to it like any other.
     *
     * @throws \Throwable
     */
    public function testAPreAuthorizedCodeIdentifyingItsWalletSatisfiesTheDiipRules(): void
    {
        $this->accessTokenMock = $this->createMock(AccessTokenEntity::class);
        $this->accessTokenMock->method('getFlowTypeEnum')->willReturn(FlowTypeEnum::VciPreAuthorizedCode);
        $this->accessTokenMock->method('getBoundClientId')->willReturn(self::HOLDER_DID_WEB);

        $validatedProofs = $this->sut()->validateRequest(
            $this->requestWith([
                'getIssuer' => self::HOLDER_DID_WEB,
                'getKeyId' => self::HOLDER_DID_WEB_URL,
            ]),
            VciCredentialBindingPolicyEnum::DiipProofBound,
            $this->accessTokenMock,
        );

        $this->assertNotNull($validatedProofs[0]);
        $this->assertSame(self::HOLDER_DID_WEB, $validatedProofs[0]->getSubject());
    }
}
