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

namespace SimpleSAML\Module\oidc\Repositories;

use SimpleSAML\Configuration;
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Services\ConfigurationService;

abstract class AbstractDatabaseRepository
{
    /**
     * @var \SimpleSAML\Configuration
     */
    protected $config;

    /**
     * @var \SimpleSAML\Database
     */
    protected $database;

    /**
     * @var \SimpleSAML\Module\oidc\Services\ConfigurationService
     */
    protected $configurationService;

    /**
     * ClientRepository constructor.
     */
    public function __construct(ConfigurationService $configurationService)
    {
        $this->config = Configuration::getOptionalConfig('module_oidc.php');
        $this->database = Database::getInstance();
        $this->configurationService = $configurationService;
    }

    /**
     * @return string|null
     */
    abstract public function getTableName();
}
