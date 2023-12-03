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

use Exception;
use SimpleSAML\Configuration;
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\ModuleConfig;

abstract class AbstractDatabaseRepository
{
    protected Configuration $config;

    protected Database $database;

    /**
     * ClientRepository constructor.
     * @throws Exception
     */
    public function __construct(protected ModuleConfig $moduleConfig)
    {
        $this->config = $this->moduleConfig->config();
        // TODO mivanci move to Doctrine DBAL stores
        $this->database = Database::getInstance();
    }

    abstract public function getTableName(): ?string;
}
