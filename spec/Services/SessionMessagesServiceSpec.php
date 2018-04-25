<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * (c) Sergio Gómez <sergio@uco.es>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\SimpleSAML\Modules\OpenIDConnect\Services;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use SimpleSAML\Modules\OpenIDConnect\Services\SessionMessagesService;

class SessionMessagesServiceSpec extends ObjectBehavior
{
    public function let(\SimpleSAML_Session $session)
    {
        $this->beConstructedWith($session);
    }

    public function it_is_initializable()
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
