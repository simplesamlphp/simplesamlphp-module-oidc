<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Codebooks;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum;

#[CoversClass(FlowTypeEnum::class)]
#[AllowMockObjectsWithoutExpectations]
class FlowTypeEnumTest extends TestCase
{
    /**
     * @return array<string, array{0: \SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum, 1: bool, 2: bool}>
     */
    public static function flowProvider(): array
    {
        return [
            // A plain OAuth 2.0 authorization code belongs to neither OpenID Connect nor OpenID4VCI, so it gets
            // neither the access token lifetime nor the key binding rules of a credential flow.
            'plain OAuth 2.0 authorization code' => [FlowTypeEnum::OAuth2AuthorizationCode, false, false],
            'OIDC authorization code' => [FlowTypeEnum::OidcAuthorizationCode, true, false],
            'OIDC implicit' => [FlowTypeEnum::OidcImplicit, true, false],
            'OIDC hybrid' => [FlowTypeEnum::OidcHybrid, true, false],
            'OIDC refresh token' => [FlowTypeEnum::OidcRefreshToken, false, false],
            'VCI authorization code' => [FlowTypeEnum::VciAuthorizationCode, false, true],
            'VCI pre-authorized code' => [FlowTypeEnum::VciPreAuthorizedCode, false, true],
        ];
    }


    #[DataProvider('flowProvider')]
    public function testTellsWhichFamilyAFlowBelongsTo(FlowTypeEnum $flow, bool $isOidc, bool $isVci): void
    {
        $this->assertSame($isOidc, $flow->isOidcFlow());
        $this->assertSame($isVci, $flow->isVciFlow());
    }


    /**
     * The provider above names every case, so one added later has to be placed in a family there.
     */
    public function testTheProviderNamesEveryFlow(): void
    {
        $named = array_map(static fn(array $row): FlowTypeEnum => $row[0], self::flowProvider());

        foreach (FlowTypeEnum::cases() as $case) {
            $this->assertContains($case, $named, sprintf('%s is not in the provider.', $case->name));
        }
    }
}
