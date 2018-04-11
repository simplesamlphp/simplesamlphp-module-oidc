<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * (c) Sergio Gómez <sergio@uco.es>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Modules\OpenIDConnect\Services;

class SessionMessagesService
{
    private $session;

    public function __construct(\SimpleSAML_Session $session)
    {
        $this->session = $session;
    }

    public function addMessage(string $value)
    {
        $this->session->setData('message', uniqid(), $value);
    }

    public function getMessages()
    {
        $messages = $this->session->getDataOfType('message');

        foreach ($messages as $key => $message) {
            $this->session->deleteData('message', $key);
        }

        return $messages;
    }
}
