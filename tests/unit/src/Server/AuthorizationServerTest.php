<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\TestCase;

/**
 * @covers \SimpleSAML\Module\oidc\Server\AuthorizationServer
 */
#[AllowMockObjectsWithoutExpectations]
class AuthorizationServerTest extends TestCase
{
    public function testValidateLogoutRequest(): never
    {
        $this->markTestIncomplete();
    }
}
