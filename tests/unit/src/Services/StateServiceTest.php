<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Services;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Services\StateService;

/**
 * @covers \SimpleSAML\Module\oidc\Services\StateService
 */
#[AllowMockObjectsWithoutExpectations]
class StateServiceTest extends TestCase
{
    /**
     * @return \SimpleSAML\Module\oidc\Services\StateService
     */
    protected function mock(): StateService
    {
        return new StateService();
    }


    /**
     * @return void
     */
    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            StateService::class,
            $this->mock(),
        );
    }
}
