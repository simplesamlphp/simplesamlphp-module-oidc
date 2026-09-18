<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Utils;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SimpleSAML\Module\oidc\Entities\ClaimSetEntity;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Factories\Entities\ClaimSetEntityFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Utils\AccessTokenClaimsResolver;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;

/**
 * What goes into the access token next to 'sub' is the intersection of two things: what the granted scopes
 * release (the extractor's job, exercised with a real one so the scope gating is the module's own) and what
 * the two options allow. Neither option can name 'sub' or an envelope claim -- ModuleConfig refuses those when
 * the lists are read -- so the resolver does not check for them again.
 */
#[CoversClass(AccessTokenClaimsResolver::class)]
#[UsesClass(ClaimTranslatorExtractor::class)]
#[UsesClass(ClaimSetEntity::class)]
#[UsesClass(ClaimSetEntityFactory::class)]
#[UsesClass(ScopeEntity::class)]
#[AllowMockObjectsWithoutExpectations]
class AccessTokenClaimsResolverTest extends TestCase
{
    protected const array USER_ATTRIBUTES = [
        'uid' => ['u1'],
        'voPersonID' => ['v1@example.org'],
        'eduPersonAssurance' => ['https://refeds.org/assurance/IAP/medium', 'https://refeds.org/assurance/ID/unique'],
        'mail' => ['u1@example.org'],
        'displayName' => ['Firsty Lasty'],
    ];

    protected const array TRANSLATION_TABLE = [
        'voperson_id' => ['voPersonID'],
        'eduperson_assurance' => ['eduPersonAssurance'],
    ];


    protected ModuleConfig&MockObject $moduleConfigMock;


    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
    }


    /**
     * @param string[] $identityClaims
     * @param string[] $accessTokenClaims
     */
    protected function sut(array $identityClaims = [], array $accessTokenClaims = []): AccessTokenClaimsResolver
    {
        $this->moduleConfigMock->method('getIdentityClaims')->willReturn($identityClaims);
        $this->moduleConfigMock->method('getAccessTokenClaims')->willReturn($accessTokenClaims);

        $claimSetEntityFactory = new ClaimSetEntityFactory();

        return new AccessTokenClaimsResolver(
            new ClaimTranslatorExtractor(
                ['uid'],
                $claimSetEntityFactory,
                [
                    // A private scope carrying the assurance, allowed multiple values.
                    $claimSetEntityFactory->build('aarc', ['eduperson_assurance']),
                    // The scope a VCI authorization_details request adds under its credential configuration id.
                    $claimSetEntityFactory->build('UniversityDegreeCredential', ['eduperson_assurance']),
                ],
                self::TRANSLATION_TABLE,
                ['eduperson_assurance'],
                $identityClaims,
            ),
            $this->moduleConfigMock,
        );
    }


    protected function user(array $claims = self::USER_ATTRIBUTES): UserEntity
    {
        $user = $this->createMock(UserEntity::class);
        $user->method('getIdentifier')->willReturn('u1');
        $user->method('getClaims')->willReturn($claims);

        return $user;
    }


    public function testResolvesNothingWhenNeitherOptionIsSet(): void
    {
        $user = $this->user();
        // No claim can pass, so the attributes are not even read.
        $user->expects($this->never())->method('getClaims');

        $this->assertSame([], $this->sut()->resolve($user, ['openid', 'aarc', 'email']));
    }


    /**
     * The identity claims ride on the 'openid' scope, which every authorization request carries.
     */
    public function testReleasesAnIdentityClaimUnderTheOpenIdScope(): void
    {
        $this->assertSame(
            ['voperson_id' => 'v1@example.org'],
            $this->sut(['voperson_id'])->resolve($this->user(), ['openid']),
        );
    }


    /**
     * An access token claim needs a granted scope which carries it: the token never says more than the
     * UserInfo endpoint would for the same grant.
     */
    public function testReleasesAnAccessTokenClaimOnlyUnderAGrantedScopeWhichCarriesIt(): void
    {
        $sut = $this->sut([], ['eduperson_assurance']);

        $this->assertSame([], $sut->resolve($this->user(), ['openid', 'email']));
        $this->assertSame(
            ['eduperson_assurance' => self::USER_ATTRIBUTES['eduPersonAssurance']],
            $sut->resolve($this->user(), ['openid', 'aarc']),
        );
    }


    /**
     * The scopes come as entities from the grants, and the credential configuration id a wallet's
     * authorization_details request turns into a scope authorises the claim like any other scope would.
     */
    public function testAcceptsScopeEntitiesAndACredentialConfigurationIdScope(): void
    {
        $this->assertSame(
            ['eduperson_assurance' => self::USER_ATTRIBUTES['eduPersonAssurance']],
            $this->sut([], ['eduperson_assurance'])->resolve(
                $this->user(),
                [new ScopeEntity('openid'), new ScopeEntity('UniversityDegreeCredential')],
            ),
        );
    }


    /**
     * Whatever else the granted scopes release (the standard 'email' and 'profile' claims here) stays out
     * of the token: the allow-list is the second gate.
     */
    public function testKeepsClaimsOutsideTheTwoListsOutOfTheToken(): void
    {
        $this->assertSame(
            ['voperson_id' => 'v1@example.org', 'eduperson_assurance' => self::USER_ATTRIBUTES['eduPersonAssurance']],
            $this->sut(['voperson_id'], ['eduperson_assurance'])->resolve(
                $this->user(),
                ['openid', 'profile', 'email', 'aarc'],
            ),
        );
    }


    /**
     * A listed claim the user has no attribute for is simply absent, as it is at the UserInfo endpoint.
     */
    public function testLeavesOutAClaimTheUserHasNoValueFor(): void
    {
        $this->assertSame(
            [],
            $this->sut(['voperson_id'], ['eduperson_assurance'])->resolve(
                $this->user(['uid' => ['u1']]),
                ['openid', 'aarc'],
            ),
        );
    }


    /**
     * The extractor's release-time rule for identity claims holds on this path too.
     */
    public function testRefusesAnIdentityClaimWhichIsNotANonEmptyString(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage("'voperson_id' identity claim");

        $this->sut(['voperson_id'])->resolve($this->user(['uid' => ['u1'], 'voPersonID' => ['']]), ['openid']);
    }
}
