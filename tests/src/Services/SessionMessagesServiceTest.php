<?php

namespace SimpleSAML\Test\Module\oidc\Services;

use SimpleSAML\Module\oidc\Services\SessionMessagesService;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Session;

/**
 * @covers \SimpleSAML\Module\oidc\Services\SessionMessagesService
 */
class SessionMessagesServiceTest extends TestCase
{
    protected \PHPUnit\Framework\MockObject\MockObject $sessionMock;

    protected function setUp(): void
    {
        $this->sessionMock = $this->createMock(Session::class);
    }

    public function prepareMockedInstance(): SessionMessagesService
    {
        return new SessionMessagesService($this->sessionMock);
    }

    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            SessionMessagesService::class,
            $this->prepareMockedInstance()
        );
    }

    public function testItAddsMessage(): void
    {
        $this->sessionMock->expects($this->once())
            ->method('setData')
            ->with('message', $this->anything(), 'value');

        $this->prepareMockedInstance()->addMessage('value');
    }

    public function testItGetsMessages(): void
    {
        $this->sessionMock->expects($this->once())
            ->method('getDataOfType')
            ->with('message')
            ->willReturn(
                [
                    'msg1' => 'Message one.',
                    'msg2' => 'Message two.',
                ]
            );

        $this->sessionMock->expects($this->exactly(2))
            ->method('deleteData')
            ->with($this->callback(function ($id) {
                return ! in_array($id, ['msg1', 'msg2']);
            }));

        $this->prepareMockedInstance()->getMessages();
    }
}
