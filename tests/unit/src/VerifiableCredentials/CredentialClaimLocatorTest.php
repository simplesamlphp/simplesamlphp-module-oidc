<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\VerifiableCredentials;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\VerifiableCredentials\CredentialClaimLocator;

/**
 * Where a claim of a credential configuration lands in a credential of each format, and which claims the issuer
 * writes itself. Whether every claim the Credential Endpoint writes is listed as the issuer's is pinned against what
 * it signs (CredentialIssuerCredentialControllerTest); how a mandatory claim fares at issuance and in the
 * configuration check is pinned there and in ModuleConfigTest.
 */
#[CoversClass(CredentialClaimLocator::class)]
class CredentialClaimLocatorTest extends TestCase
{
    /**
     * As the Credential Endpoint writes a mapped attribute: an SD-JWT VC claim where its path says; a data model 2.0
     * SD-JWT claim under credentialSubject unless its parent path names it; a jwt_vc_json claim only under
     * credentialSubject, the one member of what the mapping writes its body keeps.
     */
    #[DataProvider('claimPathInCredentialProvider')]
    public function testPutsAClaimWhereTheFormatWritesAMappedAttribute(
        string $format,
        array $claimPath,
        ?array $expected,
    ): void {
        $this->assertSame($expected, (new CredentialClaimLocator())->claimPathInCredential($format, $claimPath));
    }


    public static function claimPathInCredentialProvider(): array
    {
        return [
            'dc+sd-jwt, as it is' => ['dc+sd-jwt', ['address', 'locality'], ['address', 'locality']],
            'dc+sd-jwt, with the hole a string filter leaves' => ['dc+sd-jwt', [0 => 'a', 2 => 'b'], ['a', 'b']],
            'vc+sd-jwt, rooted under credentialSubject' => [
                'vc+sd-jwt',
                ['address', 'locality'],
                ['credentialSubject', 'address', 'locality'],
            ],
            'vc+sd-jwt, already under credentialSubject' => [
                'vc+sd-jwt',
                ['credentialSubject', 'name'],
                ['credentialSubject', 'name'],
            ],
            'vc+sd-jwt, credentialSubject deeper in the parent path' => [
                'vc+sd-jwt',
                ['x', 'credentialSubject', 'name'],
                ['x', 'credentialSubject', 'name'],
            ],
            'vc+sd-jwt, a claim named credentialSubject, which is not its own parent' => [
                'vc+sd-jwt',
                ['credentialSubject'],
                ['credentialSubject', 'credentialSubject'],
            ],
            'jwt_vc_json, under credentialSubject' => [
                'jwt_vc_json',
                ['credentialSubject', 'name'],
                ['credentialSubject', 'name'],
            ],
            'jwt_vc_json, outside credentialSubject' => ['jwt_vc_json', ['name'], null],
            'jwt_vc_json, credentialSubject not first' => ['jwt_vc_json', ['x', 'credentialSubject'], null],
        ];
    }


    /**
     * Wherever the claim is, whatever writes it: a jwt_vc_json claim outside credentialSubject, which no attribute
     * reaches, is the member of the credential it names.
     */
    #[DataProvider('locateProvider')]
    public function testLocatesAClaimWhateverWritesIt(string $format, array $claimPath, array $expected): void
    {
        $this->assertSame($expected, (new CredentialClaimLocator())->locate($format, $claimPath));
    }


    public static function locateProvider(): array
    {
        return [
            'jwt_vc_json, outside credentialSubject' => ['jwt_vc_json', [1 => 'issuer'], ['issuer']],
            'jwt_vc_json, under credentialSubject' => [
                'jwt_vc_json',
                ['credentialSubject', 'name'],
                ['credentialSubject', 'name'],
            ],
            'vc+sd-jwt, rooted as a mapped attribute is' => ['vc+sd-jwt', ['name'], ['credentialSubject', 'name']],
            'dc+sd-jwt, as it is' => ['dc+sd-jwt', ['vct'], ['vct']],
        ];
    }


    /**
     * A claim the issuer writes, one inside it, or one holding it; not one beside it, not one of another format's,
     * and none of a format the issuer does not issue.
     */
    #[DataProvider('issuerWrittenProvider')]
    public function testTellsTheClaimsTheIssuerWrites(string $format, array $location, bool $expected): void
    {
        $this->assertSame($expected, (new CredentialClaimLocator())->isWrittenByIssuer($format, $location));
    }


    public static function issuerWrittenProvider(): array
    {
        return [
            'dc+sd-jwt vct' => ['dc+sd-jwt', ['vct'], true],
            'dc+sd-jwt, inside cnf' => ['dc+sd-jwt', ['cnf', 'jwk'], true],
            'dc+sd-jwt, a user claim' => ['dc+sd-jwt', ['given_name'], false],
            'dc+sd-jwt, a subject id, which only the data model formats have' => [
                'dc+sd-jwt',
                ['credentialSubject', 'id'],
                false,
            ],
            'vc+sd-jwt subject id' => ['vc+sd-jwt', ['credentialSubject', 'id'], true],
            'vc+sd-jwt, a user claim in the subject' => ['vc+sd-jwt', ['credentialSubject', 'name'], false],
            'vc+sd-jwt, a vct, which it does not have' => ['vc+sd-jwt', ['vct'], false],
            'jwt_vc_json, the subject holding its id' => ['jwt_vc_json', ['credentialSubject'], true],
            'jwt_vc_json issuer' => ['jwt_vc_json', ['issuer'], true],
            'jwt_vc_json, a JWT claim beside the credential' => ['jwt_vc_json', ['iss'], false],
            'jwt_vc_json, a user claim in the subject' => ['jwt_vc_json', ['credentialSubject', 'name'], false],
            'a format the issuer does not issue' => ['mso_mdoc', ['vct'], false],
        ];
    }


    /**
     * What is written may give a claim from at it, around it or inside it; not from beside it. Components compare
     * strictly: a member '0' is not the index 0, and a member is not a null, which selects every element.
     */
    #[DataProvider('writtenByProvider')]
    public function testTellsWhetherWhatIsWrittenMayGiveAClaim(
        array $location,
        array $writtenLocations,
        bool $expected,
    ): void {
        $this->assertSame($expected, (new CredentialClaimLocator())->isWrittenBy($location, $writtenLocations));
    }


    public static function writtenByProvider(): array
    {
        return [
            'at it' => [['address'], [['address']], true],
            'around it' => [['address', 'locality'], [['address']], true],
            'inside it' => [['address'], [['address', 'locality']], true],
            'around every element' => [['nationalities', null], [['nationalities']], true],
            // Judged by the member before the index, which a member named like it is written inside.
            'an index, by the member before it' => [['nationalities', 0], [['nationalities', '0']], true],
            'a pointer which starts with every element' => [[null, 'code'], [['code']], false],
            'a pointer which starts with an index' => [[0], [['address']], false],
            'beside it' => [['address', 'locality'], [['address', 'country']], false],
            'elsewhere' => [['address'], [['name']], false],
            'nothing written' => [['address'], [], false],
            'one of several written' => [['address'], [['name'], ['address', 'locality']], true],
            'a member named like an index is not another member' => [['address', '0'], [['address', '00']], false],
            'a member of every element, by the member before the null' => [
                ['nationalities', null, 'code'],
                [['nationalities', 'code']],
                true,
            ],
        ];
    }
}
