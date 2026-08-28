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
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Services\NonceService;
use SimpleSAML\Module\oidc\VerifiableCredentials\OpenId4VciProofValidator;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmBag;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Did;
use SimpleSAML\OpenID\Did\DidJwkResolver;
use SimpleSAML\OpenID\Did\DidKeyJwkResolver;
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

    protected MockObject $didKeyResolverMock;

    protected MockObject $accessTokenMock;


    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->verifiableCredentialsMock = $this->createMock(VerifiableCredentialsService::class);
        $this->didMock = $this->createMock(Did::class);
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

        $this->didJwkResolverMock = $this->createMock(DidJwkResolver::class);
        $this->didKeyResolverMock = $this->createMock(DidKeyJwkResolver::class);
        $this->didMock->method('didJwkResolver')->willReturn($this->didJwkResolverMock);
        $this->didMock->method('didKeyResolver')->willReturn($this->didKeyResolverMock);
        $this->didJwkResolverMock->method('extractJwkFromDidJwk')->willReturn(self::PUBLIC_EC_JWK);
        $this->didJwkResolverMock->method('generateDidJwkFromJwk')->willReturn(self::HOLDER_DID);
        $this->didKeyResolverMock->method('extractJwkFromDidKey')->willReturn(self::PUBLIC_EC_JWK);

        $this->nonceServiceMock->method('validateNonce')->willReturn(true);

        // An authenticated wallet by default, so the anonymous pre-authorized rules are opted into by
        // the tests which are about them rather than applying everywhere.
        $clientMock = $this->createMock(ClientEntityInterface::class);
        $clientMock->method('getIdentifier')->willReturn(self::CLIENT_ID);
        $this->accessTokenMock = $this->createMock(AccessTokenEntity::class);
        $this->accessTokenMock->method('getFlowTypeEnum')->willReturn(FlowTypeEnum::VciAuthorizationCode);
        $this->accessTokenMock->method('getBoundClientId')->willReturn(null);
        $this->accessTokenMock->method('getClient')->willReturn($clientMock);
    }


    protected function sut(): OpenId4VciProofValidator
    {
        return new OpenId4VciProofValidator(
            $this->moduleConfigMock,
            $this->verifiableCredentialsMock,
            $this->didMock,
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
     * @param array<array-key,mixed> $requestData
     */
    protected function assertRefusedWith(
        string $expectedErrorCode,
        array $requestData,
        VciCredentialBindingPolicyEnum $bindingPolicy = VciCredentialBindingPolicyEnum::ProofBound,
    ): void {
        try {
            $this->sut()->validateRequest($requestData, $bindingPolicy, $this->accessTokenMock);
        } catch (CredentialRequestException $credentialRequestException) {
            $this->assertSame($expectedErrorCode, $credentialRequestException->getErrorCode());

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
     * `did:web` arrives in a later step; until then an unresolvable method has to be refused rather than
     * fallen through, which is what left proofs unverified.
     */
    public function testRefusesAVerificationMethodItCanNotResolve(): void
    {
        $this->assertRefusedWith('invalid_proof', $this->requestWith(['getKeyId' => 'did:web:example.org#0']));
        $this->assertRefusedWith('invalid_proof', $this->requestWith(['getKeyId' => 'not-a-did']));
    }


    public function testRefusesAVerificationMethodWhichFailsToResolve(): void
    {
        $didJwkResolverMock = $this->createMock(DidJwkResolver::class);
        $didJwkResolverMock->method('extractJwkFromDidJwk')->willThrowException(new DidException('malformed'));
        $this->didMock = $this->createMock(Did::class);
        $this->didMock->method('didJwkResolver')->willReturn($didJwkResolverMock);

        $this->assertRefusedWith('invalid_proof', $this->requestWith());
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
}
