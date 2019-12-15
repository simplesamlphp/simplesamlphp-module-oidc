<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * Copyright (C) 2018 by the Spanish Research and Academic Network.
 *
 * This code was developed by Universidad de Córdoba (UCO https://www.uco.es)
 * for the RedIRIS SIR service (SIR: http://www.rediris.es/sir)
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Modules\OpenIDConnect\Services;

use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseInterface;
use SimpleSAML\Error\BadRequest;
use SimpleSAML\Error\Exception;
use SimpleSAML\Utils\Auth;
use SimpleSAML\XHTML\Template;
use Zend\Diactoros\Response;
use Zend\Diactoros\Response\JsonResponse;
use Zend\Diactoros\Response\SapiEmitter;
use Zend\Diactoros\ServerRequestFactory;

class RoutingService
{
    public static function call(string $controllerClassname, bool $authenticated = true)
    {
        if ($authenticated) {
            Auth::requireAdmin();
        }

        $serverRequest = ServerRequestFactory::fromGlobals();
        if ($accept = $serverRequest->getHeader('accept')) {
            if (false !== array_search('application/json', $accept, true)) {
                self::enableJsonExceptionResponse();
            }
        }

        $container = new Container();
        $controller = self::getController($controllerClassname, $container);
        /** @var callable $controller */
        $response = $controller($serverRequest);

        if ($response instanceof Template) {
            $response->data['messages'] = $container->get(SessionMessagesService::class)->getMessages();

            return $response->show();
        }

        if ($response instanceof ResponseInterface) {
            $emitter = new SapiEmitter();

            return $emitter->emit($response);
        }

        throw new Exception('Response type not supported: '.\get_class($response));
    }

    protected static function getController(string $controllerClassname, ContainerInterface $container)
    {
        if (!class_exists($controllerClassname)) {
            throw new BadRequest("Controller does not exist: {$controllerClassname}");
        }
        $controllerReflectionClass = new \ReflectionClass($controllerClassname);

        $arguments = [];
        /** @var \ReflectionParameter $parameter */
        foreach ($controllerReflectionClass->getConstructor()->getParameters() as $parameter) {
            $className = $parameter->getClass()->getName();
            if (false === $container->has($className)) {
                throw new \RuntimeException('Parameter or service not found: '.$className);
            }

            $arguments[] = $container->get($className);
        }
        /* @var callable $controller */
        return $controllerReflectionClass->newInstanceArgs($arguments);
    }

    protected static function enableJsonExceptionResponse()
    {
        set_exception_handler(function (\Throwable $t) {
            if ($t instanceof OAuthServerException) {
                $response = $t->generateHttpResponse(new Response());
            } else {
                $error['error'] = [
                    'code' => 500,
                    'message' => $t->getMessage(),
                ];
                $response = new JsonResponse($error, 500);
            }

            $emitter = new SapiEmitter();
            $emitter->emit($response);
        });
    }
}
