<?php

namespace spec\SimpleSAML\Modules\OpenIDConnect\Services;

use SimpleSAML\Modules\OpenIDConnect\Services\SessionMessagesService;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class SessionMessagesServiceSpec extends ObjectBehavior
{
    public function let(\SimpleSAML_Session $session)
    {
        $this->beConstructedWith($session);
    }
    function it_is_initializable()
    {
        $this->shouldHaveType(SessionMessagesService::class);
    }

    public function it_adds_message(\SimpleSAML_Session $session)
    {
        $session->setData('message', Argument::any(), 'value')->shouldBeCalled();

        $this->addMessage('value');
    }

    public function it_gets_messages(\SimpleSAML_Session $session)
    {
        $session->getDataOfType('message')->shouldBeCalled()->willReturn([
            'msg1' => 'Message one.',
            'msg2' => 'Message two.',
        ]);

        $session->deleteData('message', 'msg1')->shouldBeCalled();
        $session->deleteData('message', 'msg2')->shouldBeCalled();

        $this->getMessages()->shouldBe([
            'msg1' => 'Message one.',
            'msg2' => 'Message two.',
        ]);
    }
}
