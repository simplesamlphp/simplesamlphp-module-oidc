<?php

namespace SimpleSAML\Modules\OpenIDConnect\Server\ResponseTypes\Interfaces;

interface AuthTimeResponseTypeInterface
{
    /**
     * @param int $authTime
     */
    public function setAuthTime(int $authTime): void;

    /**
     * @return int|null
     */
    public function getAuthTime(): ?int;
}
