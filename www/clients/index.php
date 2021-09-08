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

use SimpleSAML\Module\oidc\Controller\ClientIndexController;
use SimpleSAML\Module\oidc\Services\AuthContextService;
use SimpleSAML\Module\oidc\Services\RoutingService;

RoutingService::callWithPermission(ClientIndexController::class, AuthContextService::PERM_CLIENT);
