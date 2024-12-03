<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Codebooks;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Codebooks\RegistrationTypeEnum;

#[CoversClass(RegistrationTypeEnum::class)]
class RegistrationTypeEnumTest extends TestCase
{
    public function testCanGetDescription(): void
    {
        $this->assertStringContainsString(
            'Manual',
            RegistrationTypeEnum::Manual->description(),
        );

        $this->assertStringContainsString(
            'Automatic',
            RegistrationTypeEnum::FederatedAutomatic->description(),
        );
    }
}
