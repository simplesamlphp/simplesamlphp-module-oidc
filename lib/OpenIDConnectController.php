<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * (c) Sergio Gómez <sergio@uco.es>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Modules\OpenIDConnect;

use League\OAuth2\Server\Exception\OAuthServerException;
use Zend\Diactoros\Response\JsonResponse;
use Zend\Diactoros\Response\SapiEmitter;

abstract class OpenIDConnectController
{
    public function __construct()
    {
        set_exception_handler(function (\Throwable $t) {
            if ($t instanceof OAuthServerException) {
                $error['error'] = [
                    'code' => $t->getHttpStatusCode(),
                    'message' => $t->getMessage(),
                    'hint' => $t->getHint(),
                ];
            } else {
                $error['error'] = [
                    'code' => 500,
                    'message' => $t->getMessage(),
                ];
            }

            $response = new JsonResponse($error, 500);
            $emitter = new SapiEmitter();
            $emitter->emit($response);
        });
    }
}
