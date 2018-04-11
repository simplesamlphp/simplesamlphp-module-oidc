<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * (c) Sergio Gómez <sergio@uco.es>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use SimpleSAML\Modules\OpenIDConnect\Controller\ClientShowController;
use SimpleSAML\Modules\OpenIDConnect\Services\RoutingService;

RoutingService::call(ClientShowController::class);
