<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Helpers;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Helpers\Random;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;

#[CoversClass(Random::class)]
class RandomTest extends TestCase
{
    protected function sut(): Random
    {
        return new Random();
    }
    public function testCanGetIdentifier(): void
    {
        $this->assertNotEmpty(
            $this->sut()->getIdentifier(),
        );
    }

    public function testGetIdentifierThrowsOnInvalidLength(): void
    {
        $this->expectException(OidcServerException::class);
        $this->expectExceptionMessage('Random');

        $this->sut()->getIdentifier(0);
    }
}
