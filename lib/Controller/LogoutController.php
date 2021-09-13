<?php

namespace SimpleSAML\Module\oidc\Controller;

use Psr\Http\Message\ResponseInterface;
use SimpleSAML\Auth\State;
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
        //      [] register logout handler during authn. Wait for acr_values branch merge, it introduces authsourceid
        //          See: \SimpleSAML\Session::registerLogoutHandler, modules/memcookie/www/auth.php:87
        //          $session = \SimpleSAML\Session::getSessionFromRequest();
        //          $session->registerLogoutHandler($sourceId, 'class', 'method');
        //      [] implement 'sid' claim in ID Token during authn.
        //      [] also note support in discovery
        //      [] store OP -> RP associations, probably using Session
        //      [x] add end_session_endpoint to discovery
        //      [] RP logout request, must support GET and POST:
        //          [] id_token_hint - optional, recommended
        //              [] ID token, use it to extract sub, aud, sid...
        //              [] check issuer, aud, (sub?)...
        //              [] check that sid is current or recently existed
        //          [] post_logout_redirect_uri - optional
        //              [wnd] must be https for public clients, optionally http for confidential
        //                  - left the same as redirect_uri
        //              [x] enable registration in client management UI
        //              [] only allow registered redirect, must be supplied together with id_token_hint
        //              [] redirect to RP after logout
        //          [] state - optional
        //              [] return with redirect to redirect_uri
        //          [wnd] ui_locales - optional
        //              [wnd] preferred language for user UI, for example to ask user to allow logout

        // [] implement Back-Channel Logout: https://openid.net/specs/openid-connect-backchannel-1_0.html
        //      []

        // [] consider implementing  Front-Channel Logout: https://openid.net/specs/openid-connect-frontchannel-1_0.html
        //      (FCL has challenges with User Agents Blocking Access to Third-Party Content:
        //      https://openid.net/specs/openid-connect-frontchannel-1_0.html#ThirdPartyContent)


        $logoutRequest = $this->authorizationServer->validateLogoutRequest($request);
        return new Response(); // ...to satisfy return type, adjust when logout handler is implemented.
    }
}
