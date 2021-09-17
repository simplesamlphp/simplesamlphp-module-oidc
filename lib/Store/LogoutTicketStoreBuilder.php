<?php

namespace SimpleSAML\Module\oidc\Store;

class LogoutTicketStoreBuilder
{
    public static function getInstance(): LogoutTicketStoreInterface
    {
        return new DbLogoutTicketStore();
    }
}
