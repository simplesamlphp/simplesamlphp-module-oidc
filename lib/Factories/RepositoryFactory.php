<?php

namespace SimpleSAML\Module\oidc\Factories;

use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\Interfaces\AccessTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Repositories\Memcache\AccessTokenRepositoryMemcache;
use SimpleSAML\Module\oidc\Services\ConfigurationService;

class RepositoryFactory
{
    public const TYPE_DATABASE = 'database';
    public const TYPE_DATABASE_AND_MEMCACHE = 'database-and-memcache';

    public const VALID_TYPES = [
        self::TYPE_DATABASE,
        self::TYPE_DATABASE_AND_MEMCACHE,
    ];

    protected ConfigurationService $configurationService;

    protected string $repositoryType = self::TYPE_DATABASE;
    protected Database $database;

    public function __construct(
        ConfigurationService $configurationService,
        Database $database = null
    ) {
        $this->configurationService = $configurationService;
        $this->database = $database ?? Database::getInstance();

        $this->repositoryType = $this->configurationService->getRepositoryType();
    }

    public function getAccessTokenRepository(): AccessTokenRepositoryInterface
    {
        switch ($this->repositoryType) {
            case self::TYPE_DATABASE:
                return new AccessTokenRepository($this->configurationService, $this->database);
            case self::TYPE_DATABASE_AND_MEMCACHE:
                return new AccessTokenRepositoryMemcache($this->configurationService, $this->database);
        }

        return new AccessTokenRepository($this->configurationService, $this->database);
    }
}
