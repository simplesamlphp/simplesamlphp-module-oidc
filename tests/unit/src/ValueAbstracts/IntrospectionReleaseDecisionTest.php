<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\ValueAbstracts;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\ValueAbstracts\IntrospectionReleaseDecision;

#[CoversClass(IntrospectionReleaseDecision::class)]
class IntrospectionReleaseDecisionTest extends TestCase
{
    public function testReleaseAllKeepsEveryGrantedScopeAndEveryMember(): void
    {
        $sut = IntrospectionReleaseDecision::releaseAll();

        $this->assertFalse($sut->isDenied());
        $this->assertSame(['openid', 'profile'], $sut->releasedScopesOf(['openid', 'profile']));
        $this->assertSame(['active' => true, 'sub' => 'x'], $sut->withholdFrom(['active' => true, 'sub' => 'x']));
    }


    public function testDenyIsDenied(): void
    {
        $this->assertTrue(IntrospectionReleaseDecision::deny()->isDenied());
    }


    /**
     * Released scopes keep the token's order, and naming a scope the token was not granted does not add it.
     */
    public function testReleasesOnlyGrantedScopesInTheTokensOrder(): void
    {
        $sut = IntrospectionReleaseDecision::release(['email', 'not-granted', 'openid']);

        $this->assertFalse($sut->isDenied());
        $this->assertSame(['openid', 'email'], $sut->releasedScopesOf(['openid', 'profile', 'email']));
    }


    public function testAnEmptyScopeListReleasesNoScope(): void
    {
        $this->assertSame([], IntrospectionReleaseDecision::release([])->releasedScopesOf(['openid']));
    }


    public function testAScopeNamedZeroIsAScope(): void
    {
        $this->assertSame(['0'], IntrospectionReleaseDecision::release(['0'])->releasedScopesOf(['openid', '0']));
    }


    /**
     * Withholding removes the named members from the assembled answer, a token member such as 'sub' as much
     * as a user claim, and leaves everything else as it was.
     */
    public function testWithholdsTheNamedMembers(): void
    {
        $sut = IntrospectionReleaseDecision::release(withheldMembers: ['sub', 'email', 'absent']);

        $this->assertSame(
            ['active' => true, 'client_id' => 'c', 'name' => 'N'],
            $sut->withholdFrom(['active' => true, 'client_id' => 'c', 'sub' => 's', 'email' => 'e', 'name' => 'N']),
        );
        $this->assertSame(['sub', 'email', 'absent'], $sut->getWithheldMembers());
    }


    #[DataProvider('protectedMemberProvider')]
    public function testRefusesToWithholdAProtectedMember(string $member): void
    {
        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage('may not withhold the member ' . $member);

        IntrospectionReleaseDecision::release(withheldMembers: ['email', $member]);
    }


    public static function protectedMemberProvider(): array
    {
        return array_combine(
            IntrospectionReleaseDecision::PROTECTED_MEMBERS,
            array_map(fn(string $member): array => [$member], IntrospectionReleaseDecision::PROTECTED_MEMBERS),
        );
    }


    /**
     * The protected set is AARC-G052 section 3's, plus 'active' and 'aud'.
     */
    public function testProtectsTheMembersDescribingTheToken(): void
    {
        $this->assertEqualsCanonicalizing(
            ['active', 'iss', 'exp', 'iat', 'nbf', 'token_type', 'client_id', 'jti', 'aud'],
            IntrospectionReleaseDecision::PROTECTED_MEMBERS,
        );
    }


    #[DataProvider('notANameProvider')]
    public function testRefusesAWithheldMemberWhichIsNotAName(mixed $member): void
    {
        $this->expectException(ConfigurationError::class);

        IntrospectionReleaseDecision::release(withheldMembers: [$member]);
    }


    #[DataProvider('notANameProvider')]
    public function testRefusesAReleasedScopeWhichIsNotAName(mixed $scope): void
    {
        $this->expectException(ConfigurationError::class);

        IntrospectionReleaseDecision::release([$scope]);
    }


    public static function notANameProvider(): array
    {
        return [
            'empty string' => [''],
            'integer' => [1],
            'null' => [null],
            'array' => [['sub']],
        ];
    }
}
