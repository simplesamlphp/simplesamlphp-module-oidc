<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Services;

use DateTimeImmutable;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\IdTokenBuilder;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Utils\SubjectResolver;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Core;
use SimpleSAML\OpenID\Core\Factories\IdTokenFactory;
use SimpleSAML\OpenID\Core\IdToken;
use SimpleSAML\OpenID\Helpers;
use SimpleSAML\OpenID\Helpers\Base64Url;
use SimpleSAML\OpenID\Helpers\DateTime;
use SimpleSAML\OpenID\Helpers\Random;
use SimpleSAML\OpenID\Helpers\Type;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPair;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairBag;

#[CoversClass(IdTokenBuilder::class)]
#[AllowMockObjectsWithoutExpectations]
class IdTokenBuilderTest extends TestCase
{
    protected MockObject $claimTranslatorExtractorMock;

    protected MockObject $coreMock;

    protected MockObject $moduleConfigMock;

    protected MockObject $protocolSignatureKeyBagMock;

    protected MockObject $protocolSignatureKeyPairMock;

    protected MockObject $idTokenFactoryMock;

    protected MockObject $userEntityMock;

    protected MockObject $accessTokenEntityMock;

    protected MockObject $clientEntityMock;

    protected MockObject $accessTokenExpiryDateTimeMock;

    protected MockObject $scopeEntityMock;

    protected MockObject $subjectResolverMock;


    protected function setUp(): void
    {
        $this->claimTranslatorExtractorMock = $this->createMock(ClaimTranslatorExtractor::class);
        $this->coreMock = $this->createMock(Core::class);
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);

        $this->protocolSignatureKeyBagMock = $this->createMock(SignatureKeyPairBag::class);

        $this->moduleConfigMock->method('getProtocolSignatureKeyPairBag')
            ->willReturn($this->protocolSignatureKeyBagMock);

        $this->protocolSignatureKeyPairMock = $this->createMock(SignatureKeyPair::class);
        $this->protocolSignatureKeyPairMock->method('getSignatureAlgorithm')
            ->willReturn(SignatureAlgorithmEnum::RS256);

        $this->protocolSignatureKeyBagMock->method('getFirstOrFail')
            ->willReturn($this->protocolSignatureKeyPairMock);

        $this->idTokenFactoryMock = $this->createMock(IdTokenFactory::class);
        $this->coreMock->method('idTokenFactory')->willReturn($this->idTokenFactoryMock);

        $this->userEntityMock = $this->createMock(UserEntity::class);
        $this->accessTokenEntityMock = $this->createMock(AccessTokenEntity::class);
        $this->subjectResolverMock = $this->createMock(SubjectResolver::class);

        $this->clientEntityMock = $this->createMock(ClientEntity::class);
        $this->accessTokenEntityMock->method('getClient')->willReturn($this->clientEntityMock);

        $this->accessTokenExpiryDateTimeMock = $this->createMock(DateTimeImmutable::class);
        $this->accessTokenEntityMock->method('getExpiryDateTime')
            ->willReturn($this->accessTokenExpiryDateTimeMock);

        $this->scopeEntityMock = $this->createMock(ScopeEntity::class);
        $this->accessTokenEntityMock->method('getScopes')->willReturn([$this->scopeEntityMock]);
    }


    protected function sut(
        ?ClaimTranslatorExtractor $claimTranslatorExtractor = null,
        ?Core $core = null,
        ?ModuleConfig $moduleConfig = null,
        ?SubjectResolver $subjectResolver = null,
    ): IdTokenBuilder {
        $claimTranslatorExtractor ??= $this->claimTranslatorExtractorMock;
        $core ??= $this->coreMock;
        $moduleConfig ??= $this->moduleConfigMock;
        $subjectResolver ??= $this->subjectResolverMock;

        return new IdTokenBuilder(
            $claimTranslatorExtractor,
            $core,
            $moduleConfig,
            $subjectResolver,
        );
    }


    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(IdTokenBuilder::class, $this->sut());
    }


    public function testCanBuild(): void
    {
        $this->moduleConfigMock->expects($this->once())->method('getIssuer')
            ->willReturn('issuer');
        $this->idTokenFactoryMock->expects($this->once())->method('fromData')
            ->with(
                $this->anything(),
                SignatureAlgorithmEnum::RS256,
                $this->arrayHasKey(ClaimsEnum::Iss->value),
            );

        // extract() is called twice: once with the openid scope for the identity claims placed next to `sub`, and
        // once with the access token scopes to gather the claims to release.
        $this->claimTranslatorExtractorMock->expects($this->exactly(2))
            ->method('extract')
            ->willReturn(['foo' => 'bar']);

        $this->claimTranslatorExtractorMock->expects($this->once())
            ->method('extractAdditionalIdTokenClaims')
            ->willReturn(['additional' => 'claim']);

        $this->assertInstanceOf(
            IdToken::class,
            $this->sut()->buildFor(
                $this->userEntityMock,
                $this->accessTokenEntityMock,
                true,
                true,
                null,
                null,
                null,
                null,
            ),
        );
    }


    /**
     * The `sub` payload value passes through the type helper, so make it return the value it is given; the other
     * helpers return fixed values.
     */
    private function stubOpenIdHelpers(): void
    {
        $typeHelperMock = $this->createMock(Type::class);
        $typeHelperMock->method('ensureNonEmptyString')->willReturnArgument(0);
        $dateTimeHelperMock = $this->createMock(DateTime::class);
        $dateTimeHelperMock->method('getUtc')->willReturn(new DateTimeImmutable());
        $randomHelperMock = $this->createMock(Random::class);
        $randomHelperMock->method('string')->willReturn('random-jti');
        $openIdHelpersMock = $this->createMock(Helpers::class);
        $openIdHelpersMock->method('type')->willReturn($typeHelperMock);
        $openIdHelpersMock->method('dateTime')->willReturn($dateTimeHelperMock);
        $openIdHelpersMock->method('random')->willReturn($randomHelperMock);
        $this->coreMock->method('helpers')->willReturn($openIdHelpersMock);
    }


    /**
     * The issued `sub` is the one the access token was minted with, so the two tokens issued together name the
     * End-User the same way, whatever the client's claim release setting -- and it is not overwritten by the `sub`
     * the 'openid' scope releases from the attributes as they are now, which on a refresh can differ from the
     * subject carried since the original authentication. A stable `sub` is relied upon elsewhere, e.g. when
     * matching an `id_token_hint`.
     */
    #[DataProvider('claimReleaseSettingProvider')]
    public function testTakesTheSubjectFromTheAccessTokenWhateverTheClaimReleaseSetting(bool $addClaimsFromScopes): void
    {
        $this->userEntityMock->method('getIdentifier')->willReturn('raw-identifier');
        $this->userEntityMock->method('getClaims')->willReturn(['uid' => ['raw-identifier']]);
        $this->accessTokenEntityMock->method('getSubject')->willReturn('carried-subject');
        $this->subjectResolverMock->expects($this->never())->method('resolve');

        $this->stubOpenIdHelpers();

        $this->claimTranslatorExtractorMock->method('extract')->willReturn(['sub' => 'live-subject']);
        $this->claimTranslatorExtractorMock->method('extractAdditionalIdTokenClaims')->willReturn([]);

        $this->idTokenFactoryMock->expects($this->once())->method('fromData')
            ->with(
                $this->anything(),
                $this->anything(),
                $this->callback(
                    fn(array $payload): bool => ($payload[ClaimsEnum::Sub->value] ?? null) === 'carried-subject',
                ),
                $this->anything(),
            );

        $this->sut()->buildFor(
            $this->userEntityMock,
            $this->accessTokenEntityMock,
            $addClaimsFromScopes,
            false,
            null,
            null,
            null,
            null,
        );
    }


    public static function claimReleaseSettingProvider(): array
    {
        return [
            'claims released in the ID token' => [true],
            'claims left to the UserInfo endpoint' => [false],
        ];
    }


    /**
     * An access token built without a subject (rehydrated from storage) has it resolved by the same rule the mint
     * applies, so the ID token still names the End-User the way every other token does.
     */
    public function testResolvesTheSubjectWhenTheAccessTokenCarriesNone(): void
    {
        $this->userEntityMock->method('getIdentifier')->willReturn('raw-identifier');
        $this->userEntityMock->method('getClaims')->willReturn(['uid' => ['raw-identifier']]);
        $this->accessTokenEntityMock->method('getSubject')->willReturn(null);
        $this->subjectResolverMock->expects($this->once())->method('resolve')
            ->with($this->userEntityMock)
            ->willReturn('resolved-subject');

        $this->stubOpenIdHelpers();

        $this->claimTranslatorExtractorMock->method('extract')->willReturn([]);
        $this->claimTranslatorExtractorMock->method('extractAdditionalIdTokenClaims')->willReturn([]);

        $this->idTokenFactoryMock->expects($this->once())->method('fromData')
            ->with(
                $this->anything(),
                $this->anything(),
                $this->callback(
                    fn(array $payload): bool => ($payload[ClaimsEnum::Sub->value] ?? null) === 'resolved-subject',
                ),
                $this->anything(),
            );

        $this->sut()->buildFor(
            $this->userEntityMock,
            $this->accessTokenEntityMock,
            false,
            false,
            null,
            null,
            null,
            null,
        );
    }


    /**
     * The subject is REQUIRED, so it must be kept even when its value would be considered falsy (e.g. "0") -- and
     * so is a nonce, acr or sid of "0": a value the client sent or the source asserted, not an absent one. Only
     * what is absent (null, '') is left out.
     */
    public function testKeepsFalsyButPresentClaimValues(): void
    {
        $this->userEntityMock->method('getIdentifier')->willReturn('0');
        $this->userEntityMock->method('getClaims')->willReturn(['uid' => ['0']]);
        $this->accessTokenEntityMock->method('getSubject')->willReturn('0');

        $this->stubOpenIdHelpers();

        $this->claimTranslatorExtractorMock->method('extract')->willReturn([]);
        $this->claimTranslatorExtractorMock->method('extractAdditionalIdTokenClaims')->willReturn([]);

        $this->idTokenFactoryMock->expects($this->once())->method('fromData')
            ->with(
                $this->anything(),
                $this->anything(),
                $this->callback(
                    fn(array $payload): bool => ($payload[ClaimsEnum::Sub->value] ?? null) === '0' &&
                        ($payload[ClaimsEnum::Nonce->value] ?? null) === '0' &&
                        ($payload[ClaimsEnum::AuthTime->value] ?? null) === 0 &&
                        ($payload[ClaimsEnum::Acr->value] ?? null) === '0' &&
                        ($payload[ClaimsEnum::Sid->value] ?? null) === '0' &&
                        !array_key_exists(ClaimsEnum::ATHash->value, $payload),
                ),
                $this->anything(),
            );

        $this->sut()->buildFor(
            $this->userEntityMock,
            $this->accessTokenEntityMock,
            false,
            false,
            '0',
            0,
            '0',
            '0',
        );
    }


    /**
     * An empty string is an absent value, as null is: neither is placed.
     */
    public function testLeavesOutAbsentOptionalClaims(): void
    {
        $this->userEntityMock->method('getIdentifier')->willReturn('raw-identifier');
        $this->userEntityMock->method('getClaims')->willReturn(['uid' => ['raw-identifier']]);
        $this->accessTokenEntityMock->method('getSubject')->willReturn('resolved-subject');

        $this->stubOpenIdHelpers();

        $this->claimTranslatorExtractorMock->method('extract')->willReturn([]);
        $this->claimTranslatorExtractorMock->method('extractAdditionalIdTokenClaims')->willReturn([]);

        $this->idTokenFactoryMock->expects($this->once())->method('fromData')
            ->with(
                $this->anything(),
                $this->anything(),
                $this->callback(
                    fn(array $payload): bool => !array_key_exists(ClaimsEnum::Nonce->value, $payload) &&
                        !array_key_exists(ClaimsEnum::AuthTime->value, $payload) &&
                        !array_key_exists(ClaimsEnum::Acr->value, $payload) &&
                        !array_key_exists(ClaimsEnum::Sid->value, $payload) &&
                        !array_key_exists(ClaimsEnum::ATHash->value, $payload),
                ),
                $this->anything(),
            );

        $this->sut()->buildFor(
            $this->userEntityMock,
            $this->accessTokenEntityMock,
            false,
            false,
            '',
            null,
            '',
            '',
        );
    }


    /**
     * An identity claim (the rest of the 'openid' claim set next to 'sub') goes wherever 'sub' goes: into the ID
     * token whatever the client's add_claims_to_id_token setting, since it identifies the End-User rather than
     * describing them -- and like 'sub' it is kept for a falsy value. The scope-released claims stay gated.
     */
    public function testPlacesTheIdentityClaimsLikeTheSubjectWhateverTheClaimReleaseSetting(): void
    {
        $this->userEntityMock->method('getIdentifier')->willReturn('raw-identifier');
        $this->userEntityMock->method('getClaims')->willReturn(['uid' => ['raw-identifier']]);
        $this->accessTokenEntityMock->method('getSubject')->willReturn('mapped-subject');

        $this->stubOpenIdHelpers();

        $this->claimTranslatorExtractorMock->method('extract')
            ->willReturnCallback(
                fn(array $scopes, array $claims): array => $scopes === ['openid'] ?
                    ['sub' => 'mapped-subject', 'voperson_id' => 'v1@example.org', 'org_serial' => '0'] :
                    ['sub' => 'mapped-subject', 'voperson_id' => 'v1@example.org', 'name' => 'Firsty Lasty'],
            );
        $this->claimTranslatorExtractorMock->method('extractAdditionalIdTokenClaims')->willReturn([]);

        $this->idTokenFactoryMock->expects($this->once())->method('fromData')
            ->with(
                $this->anything(),
                $this->anything(),
                $this->callback(
                    fn(array $payload): bool => $payload[ClaimsEnum::Sub->value] === 'mapped-subject' &&
                        $payload['voperson_id'] === 'v1@example.org' &&
                        $payload['org_serial'] === '0' &&
                        !array_key_exists('name', $payload),
                ),
                $this->anything(),
            );

        $this->sut()->buildFor(
            $this->userEntityMock,
            $this->accessTokenEntityMock,
            false,
            false,
            null,
            null,
            null,
            null,
        );
    }


    public function testWillNegotiateIdTokenSignatureAlgorithm(): void
    {
        $this->clientEntityMock->method('getIdTokenSignedResponseAlg')
            ->willReturn(SignatureAlgorithmEnum::ES256->value);

        $ecSignatureKeyPairMock = $this->createMock(SignatureKeyPair::class);
        $ecSignatureKeyPairMock->method('getSignatureAlgorithm')
            ->willReturn(SignatureAlgorithmEnum::ES256);

        $this->protocolSignatureKeyBagMock->expects($this->once())
            ->method('getFirstByAlgorithmOrFail')
            ->with(SignatureAlgorithmEnum::ES256)
            ->willReturn($ecSignatureKeyPairMock);

        $this->assertInstanceOf(
            IdToken::class,
            $this->sut()->buildFor(
                $this->userEntityMock,
                $this->accessTokenEntityMock,
                true,
                true,
                null,
                null,
                null,
                null,
            ),
        );
    }


    public function testThrowsForInvalidUserEntity(): void
    {
        $userEntityInterfaceMock = $this->createMock(UserEntityInterface::class);
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('ClaimSetInterface');

        $this->sut()->buildFor(
            $userEntityInterfaceMock,
            $this->accessTokenEntityMock,
            true,
            true,
            null,
            null,
            null,
            null,
        );
    }


    public function testThrowsForInvalidClientEntity(): void
    {
        $accessTokenEntityMock = $this->createMock(AccessTokenEntity::class);
        $accessTokenEntityMock->method('getClient')->willReturn(
            $this->createMock(ClientEntityInterface::class),
        );

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('ClientEntity');

        $this->sut()->buildFor(
            $this->userEntityMock,
            $accessTokenEntityMock,
            true,
            true,
            null,
            null,
            null,
            null,
        );
    }


    public function testGenerateAccessTokenHash(): void
    {
        $accessTokenMock = $this->createMock(AccessTokenEntity::class);
        $accessTokenMock->method('toString')->willReturn('jHkWEdUXMU1BOmNcgmVMJw');

        $base64UrlHelper = new Base64Url();
        $helpersMock = $this->createMock(Helpers::class);
        $helpersMock->method('base64Url')->willReturn($base64UrlHelper);
        $this->coreMock->method('helpers')->willReturn($helpersMock);

        $expectedAtHash = $base64UrlHelper->encode(
            substr(hash('sha256', 'jHkWEdUXMU1BOmNcgmVMJw', true), 0, 16),
        );

        $this->assertSame(
            $expectedAtHash,
            $this->sut()->generateAccessTokenHash($accessTokenMock, 'RS256'),
        );
    }


    public function testGenerateAccessTokenHashWithEdDsa(): void
    {
        $accessTokenMock = $this->createMock(AccessTokenEntity::class);
        $accessTokenMock->method('toString')->willReturn('jHkWEdUXMU1BOmNcgmVMJw');

        $base64UrlHelper = new Base64Url();
        $helpersMock = $this->createMock(Helpers::class);
        $helpersMock->method('base64Url')->willReturn($base64UrlHelper);
        $this->coreMock->method('helpers')->willReturn($helpersMock);

        $expectedAtHash = $base64UrlHelper->encode(
            substr(hash('sha512', 'jHkWEdUXMU1BOmNcgmVMJw', true), 0, 32),
        );

        $this->assertSame(
            $expectedAtHash,
            $this->sut()->generateAccessTokenHash($accessTokenMock, SignatureAlgorithmEnum::EdDSA->value),
        );
    }


    public function testGenerateAccessTokenHashThrowsForUnsupportedAlgorithm(): void
    {
        $accessTokenMock = $this->createMock(AccessTokenEntity::class);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('JWS algorithm not supported');

        $this->sut()->generateAccessTokenHash($accessTokenMock, 'UNSUPPORTED');
    }


    public function testGenerateAccessTokenHashThrowsWhenNotEntityStringRepresentationInterface(): void
    {
        $accessTokenMock = $this->createMock(AccessTokenEntityInterface::class);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('AccessTokenEntity must implement');

        $this->sut()->generateAccessTokenHash($accessTokenMock, 'RS256');
    }
}
