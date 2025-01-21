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
namespace SimpleSAML\Module\oidc\Repositories;

use SimpleSAML\Database;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;

abstract class AbstractDatabaseRepository
{
    /**
     * ClientRepository constructor.
     * @throws \Exception
     */
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly Database $database,
        protected readonly ?ProtocolCache $protocolCache,
    ) {
    }

    public function getCacheKey(string $identifier): string
    {
        return is_string($tableName = $this->getTableName()) ?
        $tableName . '_' . $identifier :
        $identifier;
    }

    abstract public function getTableName(): ?string;
}
