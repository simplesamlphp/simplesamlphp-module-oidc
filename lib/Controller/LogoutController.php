<?php

namespace SimpleSAML\Module\oidc\Controller;

use Exception;
use SimpleSAML\Error\BadRequest;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Server\AuthorizationServer;
use Laminas\Diactoros\ServerRequest;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\LogoutHandlers\BackChannelLogoutHandler;
use SimpleSAML\Module\oidc\Server\RequestTypes\LogoutRequest;
use SimpleSAML\Module\oidc\Services\AuthenticationService;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Services\SessionService;
use SimpleSAML\Module\oidc\Store\SessionLogoutTicketStoreBuilder;
use SimpleSAML\Session;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

class LogoutController
{
    protected AuthorizationServer $authorizationServer;

    protected AuthenticationService $authenticationService;

    protected SessionService $sessionService;

    protected SessionLogoutTicketStoreBuilder $sessionLogoutTicketStoreBuilder;

    protected LoggerService $loggerService;

    protected TemplateFactory $templateFactory;

    public function __construct(
        AuthorizationServer $authorizationServer,
        AuthenticationService $authenticationService,
        SessionService $sessionService,
        SessionLogoutTicketStoreBuilder $sessionLogoutTicketStoreBuilder,
        LoggerService $loggerService,
        TemplateFactory $templateFactory
    ) {
        $this->authorizationServer = $authorizationServer;
        $this->authenticationService = $authenticationService;
        $this->sessionService = $sessionService;
        $this->sessionLogoutTicketStoreBuilder = $sessionLogoutTicketStoreBuilder;
        $this->loggerService = $loggerService;
        $this->templateFactory = $templateFactory;
    }

    /**
     * @throws BadRequest
     * @throws OidcServerException
     * @throws Throwable
     */
    public function __invoke(ServerRequest $request): Response
    {
        // TODO Back-Channel Logout: https://openid.net/specs/openid-connect-backchannel-1_0.html
        //      [] Refresh tokens issued without the offline_access property to a session being logged out SHOULD
        //           be revoked. Refresh tokens issued with the offline_access property normally SHOULD NOT be revoked.
        //      - currently we don't handle offline_access at all...

        // TODO Consider implementing Front-Channel Logout:
        //      https://openid.net/specs/openid-connect-frontchannel-1_0.html
        //      (FCL has challenges with User Agents Blocking Access to Third-Party Content:
        //      https://openid.net/specs/openid-connect-frontchannel-1_0.html#ThirdPartyContent)

        $logoutRequest = $this->authorizationServer->validateLogoutRequest($request);

        // Set indication that the logout is initiated using OIDC protocol. This will be checked in the
        // logoutHandler() method.
        $this->sessionService->setIsOidcInitiatedLogout(true);

        // Indication if any there was a call to logout action on any auth source at all...
        $wasLogoutActionCalled = false;

        $sidClaim = null;

        // If id_token_hint was provided, resolve session ID
        $idTokenHint = $logoutRequest->getIdTokenHint();
        if ($idTokenHint !== null) {
            $sidClaim = $idTokenHint->claims()->get('sid');
        }

        // Check if RP is requesting logout for session that previously existed (not this current session).
        // Claim 'sid' from 'id_token_hint' logout parameter indicates for which session should logout be
        // performed (sid is session ID used when ID token was issued during authn). If the requested
        // sid is different from the current session ID, try to find the requested session.
        if (
            $sidClaim !== null &&
            $this->sessionService->getCurrentSession()->getSessionId() !== $sidClaim
        ) {
            try {
                if (($sidSession = $this->sessionService->getSessionById($sidClaim)) !== null) {
                    $sidSessionValidAuthorities = $sidSession->getAuthorities();

                    if (! empty($sidSessionValidAuthorities)) {
                        $wasLogoutActionCalled = true;
                        // Create a SessionLogoutTicket so that the sid is available in the static logoutHandler()
                        $this->sessionLogoutTicketStoreBuilder->getInstance()->add($sidClaim);
                        // Initiate logout for every valid auth source for the requested session.
                        foreach ($sidSessionValidAuthorities as $authSourceId) {
                            $sidSession->doLogout($authSourceId);
                        }
                    }
                }
            } catch (Throwable $exception) {
                $this->loggerService->warning(
                    sprintf('Logout: could not get session with ID %s, error: %s', $sidClaim, $exception->getMessage())
                );
            }
        }

        $currentSessionValidAuthorities = $this->sessionService->getCurrentSession()->getAuthorities();
        if (! empty($currentSessionValidAuthorities)) {
            $wasLogoutActionCalled = true;
            // Initiate logout for every valid auth source for the current session.
            foreach ($this->sessionService->getCurrentSession()->getAuthorities() as $authSourceId) {
                $this->sessionService->getCurrentSession()->doLogout($authSourceId);
            }
        }

        // Set indication for OIDC initiated logout back to false, so that the logoutHandler() method does not
        // run for other logout initiated actions, like (currently) re-authentication...
        $this->sessionService->setIsOidcInitiatedLogout(false);

        return $this->resolveResponse($logoutRequest, $wasLogoutActionCalled);
    }

    /**
     * Logout handler function registered using Session::registerLogoutHandler() during authn.
     * @throws Exception
     */
    public static function logoutHandler(): void
    {
        $session = Session::getSessionFromRequest();

        // Only run this handler if logout was initiated using OIDC protocol. This is important since this
        // logout handler will (currently) also be called in re-authentication cases.
        // https://groups.google.com/g/simplesamlphp/c/-uhiVE8TaF4
        if (! SessionService::getIsOidcInitiatedLogoutForSession($session)) {
            return;
        }

        $relyingPartyAssociations = SessionService::getRelyingPartyAssociationsForSession($session);
        SessionService::clearRelyingPartyAssociationsForSession($session);

        // Check for session logout tickets. If there are any, it means that the logout was initiated using OIDC RP
        // initiated flow for specific session (not current one).
        $sessionLogoutTicketStore = SessionLogoutTicketStoreBuilder::getStaticInstance();
        $sessionLogoutTickets = $sessionLogoutTicketStore->getAll();

        if (! empty($sessionLogoutTickets)) {
            foreach ($sessionLogoutTickets as $sessionLogoutTicket) {
                $sid = $sessionLogoutTicket['sid'];
                if ($sid === $session->getSessionId()) {
                    continue;
                }

                try {
                    if (($sessionLogoutTicketSession = Session::getSession($sid)) !== null) {
                        $relyingPartyAssociations = array_merge(
                            $relyingPartyAssociations,
                            SessionService::getRelyingPartyAssociationsForSession($sessionLogoutTicketSession)
                        );

                        SessionService::clearRelyingPartyAssociationsForSession($sessionLogoutTicketSession);
                    }
                } catch (Throwable $exception) {
                    LoggerService::getInstance()->warning(
                        sprintf(
                            'Session Ticket Logout: could not get session with ID %s, error: %s',
                            $sid,
                            $exception->getMessage()
                        )
                    );
                }
            }

            $sessionLogoutTicketStore->deleteMultiple(array_map(fn($slt) => $slt['sid'], $sessionLogoutTickets));
        }

        (new BackChannelLogoutHandler())->handle($relyingPartyAssociations);
    }

    protected function resolveResponse(LogoutRequest $logoutRequest, bool $wasLogoutActionCalled): Response
    {
        if (($postLogoutRedirectUri = $logoutRequest->getPostLogoutRedirectUri()) !== null) {
            if ($logoutRequest->getState() !== null) {
                $postLogoutRedirectUri .= (strstr($postLogoutRedirectUri, '?') === false) ? '?' : '&';
                $postLogoutRedirectUri .= http_build_query(['state' => $logoutRequest->getState()]);
            }

            return new RedirectResponse($postLogoutRedirectUri);
        }

        return $this->templateFactory->render('oidc:/logout.twig', [
            'wasLogoutActionCalled' => $wasLogoutActionCalled
        ]);
    }
}
