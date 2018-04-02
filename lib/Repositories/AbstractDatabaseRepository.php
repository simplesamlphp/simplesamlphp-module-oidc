<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * (c) Sergio Gómez <sergio@uco.es>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Modules\OpenIDConnect\Repositories;

use SimpleSAML\Database;

abstract class AbstractDatabaseRepository
{
    /**
     * @var \SimpleSAML_Configuration
     */
    protected $config;
    /**
     * @var Database
     */
    protected $database;

    /**
     * ClientRepository constructor.
     */
    public function __construct()
    {
        $this->config = \SimpleSAML_Configuration::getOptionalConfig('module_oidc.php');
        $this->database = Database::getInstance();
    }

    abstract public function getTableName();
}
