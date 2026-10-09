<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\VerifiableCredentials\Values;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\ValidatedOpenId4VciProof;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\VerifiableCredentials\OpenId4VciProof;

/**
 * What issuance is told to bind a credential to, once a key proof has passed every check.
 */
#[CoversClass(ValidatedOpenId4VciProof::class)]
#[AllowMockObjectsWithoutExpectations]
class ValidatedOpenId4VciProofTest extends TestCase
{
    protected const string HOLDER_DID = 'did:web:wallet.example.org';

    /** @var array<string,string> */
    protected const array HOLDER_JWK = ['kty' => 'EC', 'crv' => 'P-256', 'x' => 'x', 'y' => 'y'];


    public function testConfirmsTheVerificationMethodAProofNamed(): void
    {
        $validatedProof = new ValidatedOpenId4VciProof(
            $this->createMock(OpenId4VciProof::class),
            self::HOLDER_DID,
            self::HOLDER_DID . '#key-1',
            null,
            'thumbprint',
        );

        $this->assertSame(self::HOLDER_DID, $validatedProof->getSubject());
        $this->assertSame(
            [ClaimsEnum::Kid->value => self::HOLDER_DID . '#key-1'],
            $validatedProof->getConfirmation(),
        );
    }


    /**
     * An inline key names no verification method, so the key itself is what there is to confirm.
     * Manufacturing a verification method id for it would be inventing an identifier the wallet never
     * published.
     */
    public function testConfirmsAnInlineKeyByTheKeyItself(): void
    {
        $validatedProof = new ValidatedOpenId4VciProof(
            $this->createMock(OpenId4VciProof::class),
            self::HOLDER_DID,
            null,
            self::HOLDER_JWK,
            'thumbprint',
        );

        $this->assertNull($validatedProof->getKeyId());
        $this->assertSame('thumbprint', $validatedProof->getKeyThumbprint());
        $this->assertSame(self::HOLDER_JWK, $validatedProof->getHolderJwk());
        $this->assertSame([ClaimsEnum::Jwk->value => self::HOLDER_JWK], $validatedProof->getConfirmation());
    }


    /**
     * @return array<string,array{0:string,1:?string}>
     */
    public static function subjectDidMethodProvider(): array
    {
        return [
            'did:web' => [self::HOLDER_DID, 'did:web'],
            'did:jwk' => ['did:jwk:eyJrdHkiOiJFQyJ9', 'did:jwk'],
            'not a DID' => ['https://issuer.example.org/sub/user', null],
            'a DID without a method-specific identifier' => ['did:web', null],
            'a DID without a method' => ['did::x', null],
        ];
    }


    /**
     * What a log line may say about the holder: the method of the identifier, never the identifier.
     */
    #[DataProvider('subjectDidMethodProvider')]
    public function testNamesTheDidMethodOfTheSubject(string $subject, ?string $expectedMethod): void
    {
        $validatedProof = new ValidatedOpenId4VciProof(
            $this->createMock(OpenId4VciProof::class),
            $subject,
            null,
            null,
            'thumbprint',
        );

        $this->assertSame($expectedMethod, $validatedProof->getSubjectDidMethod());
    }


    public function testHasNothingToConfirmWhenTheProofNamedNoKey(): void
    {
        $validatedProof = new ValidatedOpenId4VciProof(
            $this->createMock(OpenId4VciProof::class),
            self::HOLDER_DID,
            null,
            null,
            'thumbprint',
        );

        $this->assertNull($validatedProof->getConfirmation());
    }
}
