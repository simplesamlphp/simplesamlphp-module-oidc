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

namespace SimpleSAML\Modules\OpenIDConnect\Services;

use SimpleSAML\Session;

class SessionMessagesService
{
    /** @var \SimpleSAML\Session */
    private $session;

    public function __construct(Session $session)
    {
        $this->session = $session;
    }

    /**
     * @return void
     */
    public function addMessage(string $value)
    {
        $this->session->setData('message', uniqid(), $value);
    }

    /**
     * @return array
     */
    public function getMessages()
    {
        $messages = $this->session->getDataOfType('message');

        foreach ($messages as $key => $message) {
            $this->session->deleteData('message', $key);
        }

        return $messages;
    }
}
