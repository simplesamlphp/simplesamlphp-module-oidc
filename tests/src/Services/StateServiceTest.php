<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Services;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Services\StateService;

/**
 * @covers \SimpleSAML\Module\oidc\Services\StateService
 */
class StateServiceTest extends TestCase
{
    /**
     * @return StateService
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
