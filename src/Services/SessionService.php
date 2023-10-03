<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Services;

use Exception;
use SimpleSAML\Module\oidc\Server\Associations\Interfaces\RelyingPartyAssociationInterface;
use SimpleSAML\Session;

class SessionService
{
    final public const SESSION_DATA_TYPE = 'oidc';

    final public const SESSION_DATA_ID_IS_COOKIE_BASED_AUTHN = 'is-cookie-based-authn';

    final public const SESSION_DATA_ID_RP_ASSOCIATIONS = 'rp-associations';

    final public const SESSION_DATA_ID_IS_AUTHN_PERFORMED_IN_PREVIOUS_REQUEST =
        'is-authn-performed-in-previous-request';

    final public const SESSION_DATA_ID_IS_OIDC_INITIATED_LOGOUT = 'is-logout-handler-disabled';

    public function __construct(protected Session $session)
    {
    }

    public function getCurrentSession(): Session
    {
        return $this->session;
    }

    public function getSessionById(string $id): ?Session
    {
        return Session::getSession($id);
    }

    /**
     * @throws Exception
     */
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
        /** @var ?bool $isCookieBasedAuthn */
        $isCookieBasedAuthn = $this->session->getData(
            self::SESSION_DATA_TYPE,
            self::SESSION_DATA_ID_IS_COOKIE_BASED_AUTHN
        );

        if (is_bool($isCookieBasedAuthn)) {
            return $isCookieBasedAuthn;
        }

        return null;
    }

    /**
     * @throws Exception
     */
    public function addRelyingPartyAssociation(RelyingPartyAssociationInterface $association): void
    {
        $sessionId = $association->getSessionId();
        if (empty($sessionId)) {
            return;
        }

        $associationId = hash('sha256', $association->getClientId() . $sessionId);
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

    /**
     * @return array<RelyingPartyAssociationInterface>
     */
    public static function getRelyingPartyAssociationsForSession(Session $session): array
    {
        $relyingPartyAssociations = $session->getData(self::SESSION_DATA_TYPE, self::SESSION_DATA_ID_RP_ASSOCIATIONS);

        if (!is_array($relyingPartyAssociations)) {
            return [];
        }

        // Make sure we only have RelyingPartyAssociations here...
        return array_filter(
            $relyingPartyAssociations,
            fn($value) => $value instanceof RelyingPartyAssociationInterface
        );
    }

    /**
     * @throws Exception
     */
    public function clearRelyingPartyAssociations(): void
    {
        self::clearRelyingPartyAssociationsForSession($this->session);
    }

    /**
     * @throws Exception
     */
    public static function clearRelyingPartyAssociationsForSession(Session $session): void
    {
        $session->setData(
            self::SESSION_DATA_TYPE,
            self::SESSION_DATA_ID_RP_ASSOCIATIONS,
            [],
            Session::DATA_TIMEOUT_SESSION_END
        );
    }

    /**
     * @throws Exception
     */
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
     * @throws Exception
     */
    public function registerLogoutHandler(string $authSourceId, string $className, string $functionName): void
    {
        $this->session->registerLogoutHandler($authSourceId, $className, $functionName);
    }

    /**
     * Set indication if logout was initiated using OIDC protocol.
     * @throws Exception
     */
    public function setIsOidcInitiatedLogout(bool $isOidcInitiatedLogout): void
    {
        $this->session->setData(
            self::SESSION_DATA_TYPE,
            self::SESSION_DATA_ID_IS_OIDC_INITIATED_LOGOUT,
            $isOidcInitiatedLogout,
            Session::DATA_TIMEOUT_SESSION_END
        );
    }

    /**
     * Helper method to get indication if logout was initiated using OIDC protocol for given session.
     */
    public static function getIsOidcInitiatedLogoutForSession(Session $session): bool
    {
        return (bool) $session->getData(
            self::SESSION_DATA_TYPE,
            self::SESSION_DATA_ID_IS_OIDC_INITIATED_LOGOUT,
        );
    }
}
