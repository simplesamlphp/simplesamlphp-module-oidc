<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Stores\Session;

interface LogoutTicketStoreInterface
{
    public function add(string $sid): void;
    public function getAll(): array;

    /**
     * @param string[] $sids
     * @return void
     */
    public function deleteMultiple(array $sids): void;
}
