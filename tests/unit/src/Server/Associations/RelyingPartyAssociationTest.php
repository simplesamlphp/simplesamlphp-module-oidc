<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Server\Associations;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Server\Associations\RelyingPartyAssociation;

/**
 * @covers \SimpleSAML\Module\oidc\Server\Associations\RelyingPartyAssociation
 */
class RelyingPartyAssociationTest extends TestCase
{
    protected string $clientId = 'client123';
    protected string $userId = 'user123';
    protected string $sessionId = 'session123';
    protected string $backChannelLogoutUri = 'https//example.org/logout';

    public function testConstruct(): void
    {
        $rpAssociation = new RelyingPartyAssociation(
            $this->clientId,
            $this->userId,
            $this->sessionId,
            $this->backChannelLogoutUri,
        );

        $this->assertEquals($this->clientId, $rpAssociation->getClientId());
        $this->assertEquals($this->userId, $rpAssociation->getUserId());
        $this->assertEquals($this->sessionId, $rpAssociation->getSessionId());
        $this->assertEquals($this->backChannelLogoutUri, $rpAssociation->getBackChannelLogoutUri());

        $newClientId = 'newClient123';
        $newUserId = 'newUser123';
        $newSessionId = 'newSession123';
        $newBackChannelLogoutUri = 'https//new.example.org/logout';

        $rpAssociation->setClientId($newClientId);
        $rpAssociation->setUserId($newUserId);
        $rpAssociation->setSessionId($newSessionId);
        $rpAssociation->setBackChannelLogoutUri($newBackChannelLogoutUri);

        $this->assertEquals($newClientId, $rpAssociation->getClientId());
        $this->assertEquals($newUserId, $rpAssociation->getUserId());
        $this->assertEquals($newSessionId, $rpAssociation->getSessionId());
        $this->assertEquals($newBackChannelLogoutUri, $rpAssociation->getBackChannelLogoutUri());
    }
}
