<?php

namespace SimpleSAML\Module\oidc\Store;

class SessionLogoutTicketStoreBuilder
{
    public static function getInstance(): SessionLogoutTicketStoreInterface
    {
        // For now, we only have DB version implemented...
        return new SessionLogoutTicketStoreDb();
    }
}
