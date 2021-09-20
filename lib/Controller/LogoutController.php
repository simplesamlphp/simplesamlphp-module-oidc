<?php

namespace SimpleSAML\Module\oidc\Controller;

use Psr\Http\Message\ResponseInterface;
use SimpleSAML\Module\oidc\Server\AuthorizationServer;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\LogoutHandlers\BackchannelLogoutHandler;
use SimpleSAML\Module\oidc\Server\RequestTypes\LogoutRequest;
use SimpleSAML\Module\oidc\Services\AuthenticationService;
use SimpleSAML\Module\oidc\Services\SessionService;
use SimpleSAML\Module\oidc\Store\SessionLogoutTicketStoreBuilder;
use SimpleSAML\Session;

class LogoutController
{
    /**
     * @var AuthorizationServer
     */
    protected $authorizationServer;

    /**
     * @var AuthenticationService
     */
    protected $authenticationService;

    /**
     * @var SessionService
     */
    protected $sessionService;

    public function __construct(
        AuthorizationServer $authorizationServer,
        AuthenticationService $authenticationService,
        SessionService $sessionService
    ) {
        $this->authorizationServer = $authorizationServer;
        $this->authenticationService = $authenticationService;
        $this->sessionService = $sessionService;
    }

    public function __invoke(ServerRequest $request): ResponseInterface
    {
        // TODO mivanci logout
        // [] RP-Initiated Logout: https://openid.net/specs/openid-connect-rpinitiated-1_0.html
        //      [x] register logout handler during authn.
        //          See: \SimpleSAML\Session::registerLogoutHandler, modules/memcookie/www/auth.php:87
        //          $session = \SimpleSAML\Session::getSessionFromRequest();
        //          $session->registerLogoutHandler($sourceId, 'class', 'method');
        //      [x] implement 'sid' claim in ID Token during authn.
        //      [x] store OP -> RP associations, probably using Session
        //      [x] add end_session_endpoint to discovery
        //      [x] RP initiated logout request, must support GET and POST:
        //          [x] id_token_hint - optional, recommended
        //              [x] ID token, use it to extract sub, aud, sid...
        //              [x] check issuer, aud, (sub?)...
        //              [x] check that sid is current or recently existed
        //          [x] post_logout_redirect_uri - optional
        //              [wnd] must be https for public clients, optionally http for confidential
        //                  - left the same validation regex as redirect_uri
        //              [x] enable registration in client management UI
        //              [x] only allow registered redirect, must be supplied together with id_token_hint
        //              [x] redirect to RP after logout
        //          [x] state - optional
        //              [x] return with redirect to redirect_uri
        //          [wnd] ui_locales - optional
        //              [wnd] preferred language for user UI, for example to ask user to allow logout

        // [] implement Back-Channel Logout: https://openid.net/specs/openid-connect-backchannel-1_0.html
        //      [x] create Logout Token builder
        //          [x] implement claims as per https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken
        //      [] indicate BCL using backchannel_logout_supported property in discovery
        //      [] indicate sid support in Logout Token using backchannel_logout_session_supported property in discovery
        //      [x] enable clients to register backchannel_logout_uri (https but http allowed if confidential)
        //          MAY contain port, path, and query parameter components, but no fragment.
        //      [wnd] enable clients to register backchannel_logout_session_required property
        //          - wnd since we will support sid
        //      [] send logout requests with logout token, in parallel, to every associated RP
        //          [] use POST method, with logout_token as body parameter
        //          [] check if RP responded with 200 OK, consider logging if other
        //                 https://openid.net/specs/openid-connect-backchannel-1_0.html#BCResponse
        //      [] Refresh tokens issued without the offline_access property to a session being logged out SHOULD
        //           be revoked. Refresh tokens issued with the offline_access property normally SHOULD NOT be revoked.

        // [] Replace current ID token builder with generic JwtTokenBuilderService

        // [] consider implementing Front-Channel Logout: https://openid.net/specs/openid-connect-frontchannel-1_0.html
        //      (FCL has challenges with User Agents Blocking Access to Third-Party Content:
        //      https://openid.net/specs/openid-connect-frontchannel-1_0.html#ThirdPartyContent)


        $logoutRequest = $this->authorizationServer->validateLogoutRequest($request);

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
            $this->sessionService->getSession()->getSessionId() !== $sidClaim
        ) {
            try {
                if (($sidSession = Session::getSession($sidClaim)) !== null) {
                    $validAuthorities = $sidSession->getAuthorities();

                    if (! empty($validAuthorities)) {
                        // Create a SessionLogoutTicket so that the sid is available in the static logoutHandler()
                        SessionLogoutTicketStoreBuilder::getInstance()->add($sidClaim);
                        // Initiate logout for every valid auth source for the requested session.
                        foreach ($validAuthorities as $authSourceId) {
                            $sidSession->doLogout($authSourceId);
                        }
                    }
                }
            } catch (\Throwable $exception) {
                // TODO Log that requested session was not found
            }
        }

        // Initiate logout for every valid auth source for the current session.
        foreach ($this->sessionService->getSession()->getAuthorities() as $authSourceId) {
            $this->sessionService->getSession()->doLogout($authSourceId);
        }
        die('end');
        if ($logoutRequest->getPostLogoutRedirectUri() !== null) {
            return $this->generatePostLogoutRedirectResponse($logoutRequest);
        }

        return new Response();
    }

    /**
     * Logout handler function registered using Session::registerLogoutHandler() during authn.
     */
    public static function logoutHandler(): void
    {
        $relyingPartyAssociations = [];

        $session = Session::getSessionFromRequest();
        $relyingPartyAssociations = SessionService::getRelyingPartyAssociationsForSession($session);
        SessionService::clearRelyingPartyAssociationsForSession($session);

        // Check for session logout tickets. If there are any, it means that the logout was initiated using OIDC RP
        // initiated flow for specific session (not current one).
        $sessionLogoutTicketStore = SessionLogoutTicketStoreBuilder::getInstance();
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
                } catch (\Throwable $exception) {
                    // TODO Log this
                }
            }

            $sessionLogoutTicketStore->deleteMultiple(array_map(fn($slt) => $slt['sid'], $sessionLogoutTickets));
        }

        (new BackchannelLogoutHandler())->handle($relyingPartyAssociations);
    }

    protected function generatePostLogoutRedirectResponse(LogoutRequest $logoutRequest): Response\RedirectResponse
    {
        if (($postLogoutRedirectUri = $logoutRequest->getPostLogoutRedirectUri()) === null) {
            throw OidcServerException::serverError('Post logout redirect URI not available.');
        }

        if ($logoutRequest->getState() !== null) {
            $postLogoutRedirectUri .= (\strstr($postLogoutRedirectUri, '?') === false) ? '?' : '&';
            $postLogoutRedirectUri .= http_build_query(['state' => $logoutRequest->getState()]);
        }

        return new Response\RedirectResponse($postLogoutRedirectUri);
    }
}
