<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Stores\Session;

class LogoutTicketStoreBuilder
{
    protected static ?LogoutTicketStoreInterface $sessionLogoutTicketStore;

    public function __construct(?LogoutTicketStoreInterface $sessionLogoutTicketStore = null)
    {
        self::$sessionLogoutTicketStore = $sessionLogoutTicketStore ?? self::getDefaultSessionLogoutTicketStore();
    }

    public function getInstance(): LogoutTicketStoreInterface
    {
        return self::getStaticInstance();
    }

    public static function getStaticInstance(): LogoutTicketStoreInterface
    {
        return self::$sessionLogoutTicketStore ?? self::getDefaultSessionLogoutTicketStore();
    }

    public static function getDefaultSessionLogoutTicketStore(): LogoutTicketStoreInterface
    {
        // For now, we only have DB version implemented...
        return new LogoutTicketStoreDb();
    }
}
