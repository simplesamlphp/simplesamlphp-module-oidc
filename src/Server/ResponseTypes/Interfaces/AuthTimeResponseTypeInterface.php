<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\ResponseTypes\Interfaces;

interface AuthTimeResponseTypeInterface
{
    /**
     * @param int|null $authTime
     */
    public function setAuthTime(?int $authTime): void;

    /**
     * @return int|null
     */
    public function getAuthTime(): ?int;
}
