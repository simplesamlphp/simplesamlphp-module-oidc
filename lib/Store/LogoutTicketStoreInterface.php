<?php

namespace SimpleSAML\Module\oidc\Store;

interface LogoutTicketStoreInterface
{
    public function add(string $sid): void;
    public function delete(string $sid): void;
    public function getAll(): array;
}
