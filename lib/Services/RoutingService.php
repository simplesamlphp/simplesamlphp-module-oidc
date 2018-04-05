<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * (c) Sergio Gómez <sergio@uco.es>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Modules\OpenIDConnect\Services;

use Psr\Http\Message\ResponseInterface;
use SimpleSAML\Utils\Auth;
use Zend\Diactoros\Response\SapiEmitter;
use Zend\Diactoros\ServerRequestFactory;

class RoutingService
{
    public static function call(string $controller, string $action, bool $authenticated = true)
    {
        if (!class_exists($controller)) {
            throw new \SimpleSAML_Error_BadRequest("Controller does not exist: {$controller}");
        }

        if (!method_exists($controller, $action)) {
            throw new \SimpleSAML_Error_BadRequest("Method does not exist: {$controller}::{$action}");
        }

        if ($authenticated) {
            Auth::requireAdmin();
        }

        $container = new Container();
        $instance = new $controller($container);
        $template = $instance->$action(ServerRequestFactory::fromGlobals());

        if ($template instanceof \SimpleSAML_XHTML_Template) {
            $template->data['messages'] = $container->get(SessionMessagesService::class)->getMessages();

            return $template->show();
        }

        if ($template instanceof ResponseInterface) {
            $emitter = new SapiEmitter();

            return $emitter->emit($template);
        }

        throw new \SimpleSAML_Error_Error('Template type not supported: '.get_class($template));
    }
}
