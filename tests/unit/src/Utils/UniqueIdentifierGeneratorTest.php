<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Utils;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Utils\UniqueIdentifierGenerator;

/**
 * @covers \SimpleSAML\Module\oidc\Utils\UniqueIdentifierGenerator
 */
class UniqueIdentifierGeneratorTest extends TestCase
{
    /**
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    public function testDifferentIdentifiersCanBeGenerated(): void
    {
        $id1 = UniqueIdentifierGenerator::hitMe();
        $id2 = UniqueIdentifierGenerator::hitMe();

        $this->assertNotEquals($id1, $id2);
    }
}
