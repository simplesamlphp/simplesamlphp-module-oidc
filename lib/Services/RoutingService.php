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

use SimpleSAML\Utils\Auth;
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

        $instance = new $controller(...$arguments);
        $request = ServerRequestFactory::fromGlobals();

        /** @var \SimpleSAML_XHTML_Template $template */
        $template = $instance->$action($request);
        $template->show();
    }
}
