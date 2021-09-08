<?php

namespace SimpleSAML\Module\oidc\Controller;

use Psr\Http\Message\ResponseInterface;
use SimpleSAML\Auth\State;
use SimpleSAML\Module\oidc\Server\AuthorizationServer;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use SimpleSAML\Session;

class LogoutController
{
    /**
     * @var AuthorizationServer
     */
    private $authorizationServer;

    public function __construct(AuthorizationServer $authorizationServer)
    {
        $this->authorizationServer = $authorizationServer;
    }

    public function __invoke(ServerRequest $request): ResponseInterface
    {
        // TODO mivanci logout
        // * implement RP-Initiated Logout: https://openid.net/specs/openid-connect-rpinitiated-1_0.html
        // * implement Back-Channel Logout: https://openid.net/specs/openid-connect-backchannel-1_0.html
        // * consider implementing  Front-Channel Logout: https://openid.net/specs/openid-connect-frontchannel-1_0.html
        //   (FCL has challenges with User Agents Blocking Access to Third-Party Content:
        //   https://openid.net/specs/openid-connect-frontchannel-1_0.html#ThirdPartyContent)

        // register logout handler during authn
//        $session = \SimpleSAML\Session::getSessionFromRequest();
//        $session->registerLogoutHandler($sourceId, 'class', 'method');

//        return $this->authorizationServer->respondToLogoutRequest($request, new Response());
        return new Response(); // ...to satisfy return type, remove when logout handler is implemented.
    }
}
