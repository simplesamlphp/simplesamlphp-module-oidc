<?php

namespace SimpleSAML\Test\Module\oidc\Utils;

use League\OAuth2\Server\Exception\OAuthServerException;
use SimpleSAML\Module\oidc\Utils\UniqueIdentifierGenerator;
use PHPUnit\Framework\TestCase;

/**
 * @covers \SimpleSAML\Module\oidc\Utils\UniqueIdentifierGenerator
 */
class UniqueIdentifierGeneratorTest extends TestCase
{
    /**
     * @throws OAuthServerException
     */
    public function testDifferentIdentifiersCanBeGenerated(): void
    {
        $id1 = UniqueIdentifierGenerator::hitMe();
        $id2 = UniqueIdentifierGenerator::hitMe();

        $this->assertNotEquals($id1, $id2);
    }
}
