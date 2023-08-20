<?php

declare(strict_types=1);

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

namespace SimpleSAML\Module\oidc\Services;

use Exception;
use SimpleSAML\Session;

class SessionMessagesService
{
    /** @var Session */
    private Session $session;

    public function __construct(Session $session)
    {
        $this->session = $session;
    }

    /**
     * @param string $value
     * @return void
     * @throws Exception
     */
    public function addMessage(string $value): void
    {
        $this->session->setData('message', uniqid(), $value);
    }

    /**
     * @return array
     */
    public function getMessages(): array
    {
        /** @var array<string,string> $messages */
        $messages = $this->session->getDataOfType('message');

        foreach (array_keys($messages) as $key) {
            $this->session->deleteData('message', $key);
        }

        return $messages;
    }
}
