<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * Copyright (C) 2018 by the Spanish Research and Academic Network.
 *
 * This code was developed by Universidad de Córdoba (UCO https://www.uco.es)
 * for the RedIRIS SIR service (SIR: http://www.rediris.es/sir)
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\SimpleSAML\Modules\OpenIDConnect\Services;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use SimpleSAML\Modules\OpenIDConnect\Services\SessionMessagesService;
use SimpleSAML\Session;

class SessionMessagesServiceSpec extends ObjectBehavior
{
    public function let(Session $session)
    {
        $this->beConstructedWith($session);
    }

    public function it_is_initializable()
    {
        $this->shouldHaveType(SessionMessagesService::class);
    }

    public function it_adds_message(Session $session)
    {
        $session->setData('message', Argument::any(), 'value')->shouldBeCalled();

        $this->addMessage('value');
    }

    public function it_gets_messages(Session $session)
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
