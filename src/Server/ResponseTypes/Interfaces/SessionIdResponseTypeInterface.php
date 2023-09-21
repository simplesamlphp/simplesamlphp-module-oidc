<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\ResponseTypes\Interfaces;

interface SessionIdResponseTypeInterface
{
    public function getSessionId(): ?string;

    public function setSessionId(?string $sessionId): void;
}
