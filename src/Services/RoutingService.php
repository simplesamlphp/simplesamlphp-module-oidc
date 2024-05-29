<?php

declare(strict_types=1);

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

namespace SimpleSAML\Module\oidc\Services;

use Laminas\Diactoros\Response;
use Laminas\Diactoros\Response\JsonResponse;
use Laminas\Diactoros\ServerRequestFactory;
use Laminas\HttpHandlerRunner\Emitter\SapiEmitter;
use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseInterface;
use ReflectionClass;
use RuntimeException;
use SimpleSAML\Error;
use SimpleSAML\Utils\Auth;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;
use Throwable;

class RoutingService
{
    /**
     * @throws \Psr\Container\ContainerExceptionInterface
     * @throws \Psr\Container\NotFoundExceptionInterface
     * @throws \ReflectionException
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Error\Exception
     */
    public static function call(
        string $controllerClassname,
        bool $authenticated = true,
        bool $jsonResponse = false,
    ): void {
        if ($authenticated) {
            (new Auth())->requireAdmin();
        }

        if ($jsonResponse) {
            self::enableJsonExceptionResponse();
        }
        self::callController(new Container(), $controllerClassname);
    }

    /**
     * @throws \Exception
     * @throws \Psr\Container\ContainerExceptionInterface
     * @throws \Psr\Container\NotFoundExceptionInterface
     * @throws \ReflectionException
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Error\Exception
     */
    public static function callWithPermission(string $controllerClassname, string $permission): void
    {
        $container = new Container();
        /** @var AuthContextService $authContext */
        $authContext = $container->get(AuthContextService::class);
        $authContext->requirePermission($permission);
        self::callController($container, $controllerClassname);
    }

    /**
     * @throws \Exception
     * @throws \Psr\Container\ContainerExceptionInterface
     * @throws \Psr\Container\NotFoundExceptionInterface
     * @throws \ReflectionException
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Error\Exception
     * @psalm-suppress MixedMethodCall, MixedAssignment
     */
    private static function callController(ContainerInterface $container, string $controllerClassname): void
    {
        /** @var callable $controller */
        $controller = self::getController($controllerClassname, $container);
        $serverRequest = ServerRequestFactory::fromGlobals();
        $response = $controller($serverRequest);

        # TODO sspv2 return Symfony\Component\HttpFoundation\Response (Template instance) in SSP v2
        if ($response instanceof SymfonyResponse) {
            if ($response instanceof Template) {
                $response->data['messages'] = $container->get(SessionMessagesService::class)->getMessages();
            }

            // If not already handled, allow CORS (for JS clients).
            if (!$response->headers->has('Access-Control-Allow-Origin')) {
                $response->headers->set('Access-Control-Allow-Origin', '*');
            }


            $response->send();

            return;
        }

        if ($response instanceof ResponseInterface) {
            // If not already handled, allow CORS (for JS clients).
            if (!$response->hasHeader('Access-Control-Allow-Origin')) {
                $response = $response->withHeader('Access-Control-Allow-Origin', '*');
            }

            $emitter = new SapiEmitter();

            $emitter->emit($response);

            return;
        }

        throw new Error\Exception('Response type not supported: ' . $response::class);
    }

    /**
     * @throws \Psr\Container\ContainerExceptionInterface
     * @throws \Psr\Container\NotFoundExceptionInterface
     * @throws \ReflectionException
     * @throws \SimpleSAML\Error\BadRequest
     * @psalm-suppress MixedAssignment
     */
    protected static function getController(string $controllerClassname, ContainerInterface $container): object
    {
        if (!class_exists($controllerClassname)) {
            throw new Error\BadRequest("Controller does not exist: $controllerClassname");
        }
        $controllerReflectionClass = new ReflectionClass($controllerClassname);

        $arguments = [];
        $constructor = $controllerReflectionClass->getConstructor();

        if (null !== $constructor) {
            foreach ($constructor->getParameters() as $parameter) {
                $reflectionClass = $parameter->getClass();
                if (null === $reflectionClass) {
                    throw new RuntimeException('Parameter not found in container: ' . $parameter->getName());
                }

                $className = $reflectionClass->getName();
                if (false === $container->has($className)) {
                    throw new RuntimeException('Service not found in container: ' . $className);
                }

                $arguments[] = $container->get($className);
            }
        }

        return $controllerReflectionClass->newInstanceArgs($arguments);
    }

    /**
     * @return void
     */
    protected static function enableJsonExceptionResponse(): void
    {
        set_exception_handler(function (Throwable $t) {
            if ($t instanceof Error\Error) {
                // Showing SSP Error will also use SSP logger to log it.
                $t->show();
                return;
            } elseif ($t instanceof OAuthServerException) {
                $response = $t->generateHttpResponse(new Response());
            } else {
                $error = [];
                $error['error'] = [
                    'code' => 500,
                    'message' => $t->getMessage(),
                ];
                $response = new JsonResponse($error, 500);
            }

            // Log exception using SSP Exception logging feature.
            (Error\Exception::fromException($t))->logError();

            $emitter = new SapiEmitter();
            $emitter->emit($response);
        });
    }
}
