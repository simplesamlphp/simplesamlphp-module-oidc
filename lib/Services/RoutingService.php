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

        $reflectionClass = new \ReflectionClass($controller);
        $reflectedArguments = $reflectionClass->getConstructor()->getParameters();
        $arguments = [];

        foreach ($reflectedArguments as $reflectedArgument) {
            $className = $reflectedArgument->getClass()->getName();
            $arguments[] = new $className();
        }

        $instance = $reflectionClass->newInstanceArgs($arguments);
        $request = ServerRequestFactory::fromGlobals();
        $messages = (new SessionMessagesService())->getMessages();

        $template = $instance->$action($request);
        if ($template instanceof \SimpleSAML_XHTML_Template) {
            $template->data['messages'] = $messages;
            $template->show();
        }

        if ($template instanceof ResponseInterface) {
            $emitter = new SapiEmitter();
            $emitter->emit($template);
        }

        throw new \SimpleSAML_Error_Error('Template type not supported: '.get_class($template));
    }
}
