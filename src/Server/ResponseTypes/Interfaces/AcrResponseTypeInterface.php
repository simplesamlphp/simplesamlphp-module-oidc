<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\ResponseTypes\Interfaces;

interface AcrResponseTypeInterface
{
    public function setAcr(?string $acr): void;

    public function getAcr(): ?string;
}
