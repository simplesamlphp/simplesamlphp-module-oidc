<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SimpleSAML\Module\oidc\Exceptions\UpstreamIntrospectionException;

#[CoversClass(UpstreamIntrospectionException::class)]
class UpstreamIntrospectionExceptionTest extends TestCase
{
    public function testTellsTheDeploymentsOwnFaultFromTheUpstreams(): void
    {
        $cause = new RuntimeException('cause');

        $unavailable = UpstreamIntrospectionException::unavailable('unavailable', $cause);
        $malformed = UpstreamIntrospectionException::malformedResponse('malformed');
        $ownFault = UpstreamIntrospectionException::ownFault('own fault', $cause);

        $this->assertFalse($unavailable->isOwnFault());
        $this->assertSame('unavailable', $unavailable->getMessage());
        $this->assertSame($cause, $unavailable->getPrevious());

        $this->assertFalse($malformed->isOwnFault());
        $this->assertNull($malformed->getPrevious());

        $this->assertTrue($ownFault->isOwnFault());
        $this->assertSame('own fault', $ownFault->getMessage());
        $this->assertSame($cause, $ownFault->getPrevious());
    }
}
