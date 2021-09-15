<?php

namespace SimpleSAML\Module\oidc\Controller;

use Psr\Http\Message\ResponseInterface;
use SimpleSAML\Module\oidc\Server\AuthorizationServer;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use SimpleSAML\Module\oidc\Services\AuthenticationService;
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

    public function __construct(
        AuthorizationServer $authorizationServer,
        AuthenticationService $authenticationService
    ) {
        $this->authorizationServer = $authorizationServer;
        $this->authenticationService = $authenticationService;
    }

    public function __invoke(ServerRequest $request): ResponseInterface
    {
        // TODO mivanci logout
        // [] RP-Initiated Logout: https://openid.net/specs/openid-connect-rpinitiated-1_0.html
        //      [] register logout handler during authn.
        //          See: \SimpleSAML\Session::registerLogoutHandler, modules/memcookie/www/auth.php:87
        //          $session = \SimpleSAML\Session::getSessionFromRequest();
        //          $session->registerLogoutHandler($sourceId, 'class', 'method');
        //      [x] implement 'sid' claim in ID Token during authn.
        //      [x] store OP -> RP associations, probably using Session
        //      [x] add end_session_endpoint to discovery
        //      [] RP logout request, must support GET and POST:
        //          [] id_token_hint - optional, recommended
        //              [x] ID token, use it to extract sub, aud, sid...
        //              [x] check issuer, aud, (sub?)...
        //              [] check that sid is current or recently existed
        //          [] post_logout_redirect_uri - optional
        //              [wnd] must be https for public clients, optionally http for confidential
        //                  - left the same validation regex as redirect_uri
        //              [x] enable registration in client management UI
        //              [x] only allow registered redirect, must be supplied together with id_token_hint
        //              [] redirect to RP after logout
        //          [] state - optional
        //              [] return with redirect to redirect_uri
        //          [wnd] ui_locales - optional
        //              [wnd] preferred language for user UI, for example to ask user to allow logout

        // [] implement Back-Channel Logout: https://openid.net/specs/openid-connect-backchannel-1_0.html
        //      [] create Logout Token builder
        //          [] implement claims as per https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken
        //      [] indicate BCL using backchannel_logout_supported property in discovery
        //      [] indicate sid support in Logout Token using backchannel_logout_session_supported property in discovery
        //      [] enable clients to register backchannel_logout_uri (https but http allowed if confidential)
        //          MAY contain port, path, and query parameter components, but no fragment.
        //      [wnd] enable clients to register backchannel_logout_session_required property
        //          - wnd since we will support sid
        //      [] send logout requests with logout token, in parallel, to every associated RP
        //          [] use POST method, with logout_token as body parameter
        //          [] check if RP responded with 200 OK, consider logging if other
        //                 https://openid.net/specs/openid-connect-backchannel-1_0.html#BCResponse
        //      [] Refresh tokens issued without the offline_access property to a session being logged out SHOULD
        //           be revoked. Refresh tokens issued with the offline_access property normally SHOULD NOT be revoked.

        // [] consider implementing Front-Channel Logout: https://openid.net/specs/openid-connect-frontchannel-1_0.html
        //      (FCL has challenges with User Agents Blocking Access to Third-Party Content:
        //      https://openid.net/specs/openid-connect-frontchannel-1_0.html#ThirdPartyContent)


        $logoutRequest = $this->authorizationServer->validateLogoutRequest($request);

        // Check if RP is requesting logout for session that previously existed (not this current session).
        $sidClaim = null;
        $idTokenHint = $logoutRequest->getIdTokenHint();
        if ($idTokenHint !== null) {
            $sidClaim = $idTokenHint->claims()->get('sid');
        }

        if (
            $sidClaim !== null &&
            ($previousSession = Session::getSession($sidClaim)) !== null
        ) {
            $previousRpAssociations = $previousSession->getData(
                $this->authenticationService::SESSION_DATA_TYPE,
                $this->authenticationService::SESSION_DATA_ID_RP_ASSOCIATIONS
            ) ?? [];

            foreach ($previousRpAssociations as $clientId) {
                $this->authenticationService->markRpAssociation($clientId);
            }
        }

        $this->authenticationService->logout();

        $postLogoutRedirectUri = $logoutRequest->getPostLogoutRedirectUri();
        if ($postLogoutRedirectUri !== null) {
            return new Response\RedirectResponse($postLogoutRedirectUri);
        }

        return new Response();
    }

    /**
     * Logout handler function registered using Session::registerLogoutHandler() during authn.
     */
    public static function logoutHandler(): void
    {
        $session = Session::getSessionFromRequest();

        // TODO send BCL requests to associated RPs
    }
}
