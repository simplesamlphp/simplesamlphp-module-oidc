<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\ValueAbstracts;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\ValueAbstracts\PreAuthorizedCodeClient;

/**
 * The two shapes a wallet redeeming a pre-authorized code can be known in: a registered client, carried as
 * the entity the token is then issued to and known by that entity's identifier, and a wallet which only
 * declared an identifier, carried as that identifier and no entity.
 */
#[CoversClass(PreAuthorizedCodeClient::class)]
#[AllowMockObjectsWithoutExpectations]
class PreAuthorizedCodeClientTest extends TestCase
{
    private const string CLIENT_ID = 'https://wallet.example.org';


    public function testARegisteredClientIsCarriedAsTheEntityAndKnownByItsIdentifier(): void
    {
        $clientMock = $this->createMock(ClientEntityInterface::class);
        $clientMock->method('getIdentifier')->willReturn(self::CLIENT_ID);

        $sut = PreAuthorizedCodeClient::registered($clientMock);

        $this->assertTrue($sut->isRegistered());
        $this->assertSame($clientMock, $sut->getRegisteredClient());
        $this->assertSame(self::CLIENT_ID, $sut->getIdentifier());
    }


    public function testASelfDeclaredIdentifierIsCarriedWithNoEntity(): void
    {
        $sut = PreAuthorizedCodeClient::selfDeclared(self::CLIENT_ID);

        $this->assertFalse($sut->isRegistered());
        $this->assertNull($sut->getRegisteredClient());
        $this->assertSame(self::CLIENT_ID, $sut->getIdentifier());
    }
}
