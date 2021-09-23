<?php

namespace SimpleSAML\Module\oidc\Store;

class SessionLogoutTicketStoreBuilder
{
    protected static ?SessionLogoutTicketStoreInterface $sessionLogoutTicketStore;

    public function __construct(?SessionLogoutTicketStoreInterface $sessionLogoutTicketStore = null)
    {
        self::$sessionLogoutTicketStore = $sessionLogoutTicketStore ?? self::getDefaultSessionLogoutTicketStore();
    }

    public function getInstance(): SessionLogoutTicketStoreInterface
    {
        return self::getStaticInstance();
    }

    public static function getStaticInstance(): SessionLogoutTicketStoreInterface
    {
        return self::$sessionLogoutTicketStore ?? self::getDefaultSessionLogoutTicketStore();
    }

    public static function getDefaultSessionLogoutTicketStore(): SessionLogoutTicketStoreInterface
    {
        // For now, we only have DB version implemented...
        return new SessionLogoutTicketStoreDb();
    }
}
