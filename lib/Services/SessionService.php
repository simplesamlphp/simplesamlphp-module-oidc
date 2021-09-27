<?php

namespace SimpleSAML\Module\oidc\Services;

use SimpleSAML\Module\oidc\Server\Associations\Interfaces\RelyingPartyAssociationInterface;
use SimpleSAML\Session;

class SessionService
{
    protected Session $session;

    public const SESSION_DATA_TYPE = 'oidc';

    public const SESSION_DATA_ID_IS_COOKIE_BASED_AUTHN = 'is-cookie-based-authn';

    public const SESSION_DATA_ID_RP_ASSOCIATIONS = 'rp-associations';

    public const SESSION_DATA_ID_IS_AUTHN_PERFORMED_IN_PREVIOUS_REQUEST = 'is-authn-performed-in-previous-request';

    public const SESSION_DATA_ID_IS_LOGOUT_HANDLER_DISABLED = 'is-logout-handler-disabled';

    public function __construct(Session $session)
    {
        $this->session = $session;
    }

    public function getCurrentSession(): Session
    {
        return $this->session;
    }

    public function getSessionById(string $id): ?Session
    {
        return Session::getSession($id);
    }

    public function setIsCookieBasedAuthn(bool $isCookieBasedAuthn): void
    {
        $this->session->setData(
            self::SESSION_DATA_TYPE,
            self::SESSION_DATA_ID_IS_COOKIE_BASED_AUTHN,
            $isCookieBasedAuthn,
            Session::DATA_TIMEOUT_SESSION_END
        );
    }

    public function getIsCookieBasedAuthn(): ?bool
    {
        return $this->session->getData(
            self::SESSION_DATA_TYPE,
            self::SESSION_DATA_ID_IS_COOKIE_BASED_AUTHN
        );
    }

    public function addRelyingPartyAssociation(RelyingPartyAssociationInterface $association): void
    {
        $associationId = hash('sha256', $association->getClientId() . $association->getSessionId());
        $associations = $this->getRelyingPartyAssociations();

        if (! array_key_exists($associationId, $associations)) {
            $associations[$associationId] = $association;
        }

        $this->session->setData(
            self::SESSION_DATA_TYPE,
            self::SESSION_DATA_ID_RP_ASSOCIATIONS,
            $associations,
            Session::DATA_TIMEOUT_SESSION_END
        );
    }

    public function getRelyingPartyAssociations(): array
    {
        return self::getRelyingPartyAssociationsForSession($this->session);
    }

    public static function getRelyingPartyAssociationsForSession(Session $session): array
    {
        return $session->getData(self::SESSION_DATA_TYPE, self::SESSION_DATA_ID_RP_ASSOCIATIONS) ?? [];
    }

    public function clearRelyingPartyAssociations(): void
    {
        self::clearRelyingPartyAssociationsForSession($this->session);
    }

    public static function clearRelyingPartyAssociationsForSession(Session $session): void
    {
        $session->setData(
            self::SESSION_DATA_TYPE,
            self::SESSION_DATA_ID_RP_ASSOCIATIONS,
            [],
            Session::DATA_TIMEOUT_SESSION_END
        );
    }

    public function setIsAuthnPerformedInPreviousRequest(bool $isAuthnPerformedInPreviousRequest): void
    {
        $this->session->setData(
            self::SESSION_DATA_TYPE,
            self::SESSION_DATA_ID_IS_AUTHN_PERFORMED_IN_PREVIOUS_REQUEST,
            $isAuthnPerformedInPreviousRequest,
            Session::DATA_TIMEOUT_SESSION_END
        );
    }

    public function getIsAuthnPerformedInPreviousRequest(): bool
    {
        return (bool) $this->session->getData(
            self::SESSION_DATA_TYPE,
            self::SESSION_DATA_ID_IS_AUTHN_PERFORMED_IN_PREVIOUS_REQUEST,
        );
    }

    /**
     * @throws \Exception
     */
    public function registerLogoutHandler(string $authSourceId, string $className, string $functionName): void
    {
        $this->session->registerLogoutHandler($authSourceId, $className, $functionName);
    }

    public function setIsLogoutHandlerDisabled(bool $isLogoutHandlerDisabled): void
    {
        $this->session->setData(
            self::SESSION_DATA_TYPE,
            self::SESSION_DATA_ID_IS_LOGOUT_HANDLER_DISABLED,
            $isLogoutHandlerDisabled,
            Session::DATA_TIMEOUT_SESSION_END
        );
    }

    public function getIsLogoutHandlerDisabled(): bool
    {
        return self::getIsLogoutHandlerDisabledForSession($this->session);
    }

    public static function getIsLogoutHandlerDisabledForSession(Session $session): bool
    {
        return (bool) $session->getData(
            self::SESSION_DATA_TYPE,
            self::SESSION_DATA_ID_IS_LOGOUT_HANDLER_DISABLED,
        );
    }
}
