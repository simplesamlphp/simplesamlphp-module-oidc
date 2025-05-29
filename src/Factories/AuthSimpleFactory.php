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

namespace SimpleSAML\Module\oidc\Factories;

use SimpleSAML\Auth\Simple;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\ModuleConfig;

class AuthSimpleFactory
{
    public function __construct(
        private readonly ModuleConfig $moduleConfig,
    ) {
    }

    /**
     * @codeCoverageIgnore
     * @throws \Exception
     */
    public function build(ClientEntityInterface $clientEntity): Simple
    {
        $authSourceId = $this->resolveAuthSourceId($clientEntity);

        return new Simple($authSourceId);
    }

    /**
     * @return Simple The default authsource
     * @throws \Exception
     */
    public function getDefaultAuthSource(): Simple
    {
        return new Simple($this->moduleConfig->getDefaultAuthSourceId());
    }

    /**
     * Get auth source defined on the client. If not set on the client, get the default auth source defined in config.
     *
     * @throws \Exception
     */
    public function resolveAuthSourceId(ClientEntityInterface $client): string
    {
        return $client->getAuthSourceId() ?? $this->moduleConfig->getDefaultAuthSourceId();
    }

    public function forAuthSourceId(string $authSourceId): Simple
    {
        return new Simple($authSourceId);
    }
}
