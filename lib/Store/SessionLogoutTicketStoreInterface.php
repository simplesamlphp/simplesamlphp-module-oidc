<?php

namespace SimpleSAML\Module\oidc\Store;

interface SessionLogoutTicketStoreInterface
{
    public function add(string $sid): void;
    public function getAll(): array;
    public function delete(string $sid): void;
    public function deleteMultiple(array $sids): void;
}
