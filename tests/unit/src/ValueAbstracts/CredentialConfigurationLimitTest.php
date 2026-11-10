<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\ValueAbstracts;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\ValueAbstracts\ApiCaller;
use SimpleSAML\Module\oidc\ValueAbstracts\CredentialConfigurationLimit;

#[CoversClass(CredentialConfigurationLimit::class)]
#[CoversClass(ApiCaller::class)]
class CredentialConfigurationLimitTest extends TestCase
{
    /**
     * No limit allows every credential configuration, but not a credential whose configuration is not known,
     * which can not be said to be one of them.
     */
    public function testUnlimitedAllowsEveryConfiguration(): void
    {
        $limit = CredentialConfigurationLimit::unlimited();

        $this->assertTrue($limit->isUnlimited());
        $this->assertNull($limit->getCredentialConfigurationIds());
        $this->assertTrue($limit->allows('employee_card'));
        $this->assertTrue($limit->allows(ModuleConfig::API_TOKEN_ALL_CREDENTIAL_CONFIGURATIONS));
        $this->assertFalse($limit->allows(null));
    }


    /**
     * A limit allows exactly what it lists, compared whole and case sensitively, and never a credential whose
     * configuration is not known.
     */
    public function testALimitAllowsExactlyWhatItLists(): void
    {
        $limit = CredentialConfigurationLimit::to(['employee_card', 'library_card', 'employee_card']);

        $this->assertFalse($limit->isUnlimited());
        $this->assertSame(['employee_card', 'library_card'], $limit->getCredentialConfigurationIds());
        $this->assertTrue($limit->allows('employee_card'));
        $this->assertTrue($limit->allows('library_card'));

        foreach (['student_card', 'employee', 'employee_card_v2', 'Employee_Card', ' employee_card', '*', ''] as $id) {
            $this->assertFalse($limit->allows($id), $id);
        }

        $this->assertFalse($limit->allows(null));
    }


    public function testAnEmptyLimitAllowsNothing(): void
    {
        $limit = CredentialConfigurationLimit::to([]);

        $this->assertFalse($limit->isUnlimited());
        $this->assertSame([], $limit->getCredentialConfigurationIds());
        $this->assertFalse($limit->allows('employee_card'));
        $this->assertFalse($limit->allows(null));
    }


    /**
     * As an API token's configuration has it: no list allows none, the wildcard alone allows all. The wildcard
     * beside IDs, which the configuration refuses, is never read as all of them should it get here.
     *
     * @param ?string[] $configuredIds
     */
    #[DataProvider('configuredIdsProvider')]
    public function testReadsAnApiTokensConfiguredList(
        ?array $configuredIds,
        bool $isUnlimited,
        ?array $expectedIds,
    ): void {
        $limit = CredentialConfigurationLimit::fromConfiguredIds($configuredIds);

        $this->assertSame($isUnlimited, $limit->isUnlimited());
        $this->assertSame($expectedIds, $limit->getCredentialConfigurationIds());
        // What it allows, not only how it reads: a configuration none of the cases lists is allowed by the
        // wildcard alone.
        $this->assertSame($isUnlimited, $limit->allows('library_card'));
        $this->assertSame(
            $isUnlimited || in_array('employee_card', (array)$configuredIds, true),
            $limit->allows('employee_card'),
        );
        $this->assertFalse($limit->allows(null));
    }


    public static function configuredIdsProvider(): array
    {
        return [
            'no list' => [null, false, []],
            'an empty list' => [[], false, []],
            'the wildcard alone' => [['*'], true, null],
            'IDs' => [['employee_card', 'student_card'], false, ['employee_card', 'student_card']],
            'the wildcard beside an ID' => [['*', 'employee_card'], false, ['*', 'employee_card']],
        ];
    }


    public function testACallerCarriesItsPrincipalAndItsLimit(): void
    {
        $limit = CredentialConfigurationLimit::to(['employee_card']);
        $caller = new ApiCaller('HR system', $limit);

        $this->assertSame('HR system', $caller->getPrincipal());
        $this->assertSame($limit, $caller->getCredentialConfigurationLimit());
    }
}
