<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Store;

interface SessionLogoutTicketStoreInterface
{
    public function add(string $sid): void;
    public function getAll(): array;

    /**
     * @param string[] $sids
     * @return void
     */
    public function deleteMultiple(array $sids): void;
}
