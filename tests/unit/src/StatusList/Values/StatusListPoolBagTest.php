<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\StatusList\Values;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\Codebooks\StatusListKeyProfileEnum;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListPool;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListPoolBag;

#[CoversClass(StatusListPoolBag::class)]
#[AllowMockObjectsWithoutExpectations]
class StatusListPoolBagTest extends TestCase
{
    /**
     * @param array<array-key,mixed> $config
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    protected function sut(array $config): StatusListPoolBag
    {
        return StatusListPoolBag::fromConfig($config, StatusListKeyProfileEnum::DidJwk);
    }


    public function testAnEmptyConfigurationYieldsAnEmptyBag(): void
    {
        $bag = $this->sut([]);

        $this->assertTrue($bag->isEmpty());
        $this->assertSame([], $bag->getAll());
        $this->assertNull($bag->getForCredentialConfigurationId('Anything'));
    }


    public function testResolvesACredentialConfigurationToItsPool(): void
    {
        $bag = $this->sut([
            'degrees' => [StatusListPool::KEY_CREDENTIAL_CONFIGURATIONS => ['UniversityDegree', 'Diploma']],
            'badges' => [StatusListPool::KEY_CREDENTIAL_CONFIGURATIONS => ['EmployeeBadge']],
        ]);

        $this->assertFalse($bag->isEmpty());
        $this->assertCount(2, $bag->getAll());
        $this->assertSame('degrees', $bag->getForCredentialConfigurationId('Diploma')?->getId());
        $this->assertSame('badges', $bag->getForCredentialConfigurationId('EmployeeBadge')?->getId());
        $this->assertSame('degrees', $bag->getById('degrees')?->getId());
    }


    /**
     * A configuration in no pool is not an error: its credentials are simply issued without a status
     * claim, and so can not be revoked.
     */
    public function testACredentialConfigurationInNoPoolResolvesToNothing(): void
    {
        $bag = $this->sut([
            'degrees' => [StatusListPool::KEY_CREDENTIAL_CONFIGURATIONS => ['UniversityDegree']],
        ]);

        $this->assertNull($bag->getForCredentialConfigurationId('EmployeeBadge'));
    }


    /**
     * Allocation needs one answer to which policy a credential is issued under, so two pools claiming
     * the same configuration is a configuration error rather than something to resolve by precedence.
     */
    public function testRejectsACredentialConfigurationListedInTwoPools(): void
    {
        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage('UniversityDegree');

        $this->sut([
            'degrees' => [StatusListPool::KEY_CREDENTIAL_CONFIGURATIONS => ['UniversityDegree']],
            'others' => [StatusListPool::KEY_CREDENTIAL_CONFIGURATIONS => ['UniversityDegree']],
        ]);
    }


    public function testRejectsAPoolWhoseSettingsAreNotAnArray(): void
    {
        $this->expectException(ConfigurationError::class);

        $this->sut(['degrees' => 'UniversityDegree']);
    }


    public function testRejectsAPoolWithoutAnIdentifier(): void
    {
        $this->expectException(ConfigurationError::class);

        $this->sut([[StatusListPool::KEY_CREDENTIAL_CONFIGURATIONS => ['UniversityDegree']]]);
    }


    public function testListsEveryCredentialConfigurationItCovers(): void
    {
        $bag = $this->sut([
            'degrees' => [StatusListPool::KEY_CREDENTIAL_CONFIGURATIONS => ['UniversityDegree', 'Diploma']],
            'badges' => [StatusListPool::KEY_CREDENTIAL_CONFIGURATIONS => ['EmployeeBadge']],
        ]);

        $covered = $bag->getAllCredentialConfigurationIds();
        sort($covered);

        $this->assertSame(['Diploma', 'EmployeeBadge', 'UniversityDegree'], $covered);
    }
}
