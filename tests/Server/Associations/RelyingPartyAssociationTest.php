<?php

namespace SimpleSAML\Test\Module\oidc\Server\Associations;

use SimpleSAML\Module\oidc\Server\Associations\RelyingPartyAssociation;
use PHPUnit\Framework\TestCase;

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
        $rpAssocioantion = new RelyingPartyAssociation(
            $this->clientId,
            $this->userId,
            $this->sessionId,
            $this->backChannelLogoutUri
        );

        $this->assertEquals($this->clientId, $rpAssocioantion->getClientId());
        $this->assertEquals($this->userId, $rpAssocioantion->getUserId());
        $this->assertEquals($this->sessionId, $rpAssocioantion->getSessionId());
        $this->assertEquals($this->backChannelLogoutUri, $rpAssocioantion->getBackchannelLogoutUri());

        $newClientId = 'newClient123';
        $newUserId = 'newUser123';
        $newSessionId = 'newSession123';
        $newBackChannelLogoutUri = 'https//new.example.org/logout';

        $rpAssocioantion->setClientId($newClientId);
        $rpAssocioantion->setUserId($newUserId);
        $rpAssocioantion->setSessionId($newSessionId);
        $rpAssocioantion->setBackchannelLogoutUri($newBackChannelLogoutUri);

        $this->assertEquals($newClientId, $rpAssocioantion->getClientId());
        $this->assertEquals($newUserId, $rpAssocioantion->getUserId());
        $this->assertEquals($newSessionId, $rpAssocioantion->getSessionId());
        $this->assertEquals($newBackChannelLogoutUri, $rpAssocioantion->getBackchannelLogoutUri());
    }
}
