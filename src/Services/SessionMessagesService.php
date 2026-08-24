<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Services;

use SimpleSAML\Session;

class SessionMessagesService
{
    public function __construct(private readonly Session $session)
    {
    }


    /**
     * @throws \Exception
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
