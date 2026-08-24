<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestTypes;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\TestCase;

/**
 * @covers \SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest
 */
#[AllowMockObjectsWithoutExpectations]
class AuthorizationRequestTest extends TestCase
{
    public function testIncomplete(): never
    {
        $this->markTestIncomplete();
    }
}
