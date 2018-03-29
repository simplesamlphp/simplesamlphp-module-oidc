<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * (c) Sergio Gómez <sergio@uco.es>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Modules\OpenIDConnect\Services;

use SimpleSAML\Database;
use SimpleSAML\Modules\OpenIDConnect\Repositories\UserRepository;

class DatabaseMigration
{
    /**
     * @var Database
     */
    private $database;

    public function __construct()
    {
        $this->database = Database::getInstance();
    }

    public function migrate()
    {
        $versionsTablename = $this->database->applyPrefix('oidc_migration_versions');
        $this->database->write("CREATE TABLE IF NOT EXISTS {$versionsTablename} (version VARCHAR(255) PRIMARY KEY NOT NULL)");

        $versions = $this->database
            ->read("SELECT version FROM ${versionsTablename}")
            ->fetchAll(\PDO::FETCH_COLUMN, 0);

        if (!in_array('20180305180300', $versions, true)) {
            $this->version20180305180300();
            $this->database->write("INSERT INTO ${versionsTablename} (version) VALUES ('20180305180300')");
        }
    }

    private function version20180305180300()
    {
        $userTablename = $this->database->applyPrefix(UserRepository::TABLE_NAME);
        $this->database->write(<<< EOT
        CREATE TABLE ${userTablename} (
            id VARCHAR(255) PRIMARY KEY NOT NULL,
            claims TEXT,
            updated_at TIMESTAMP NOT NULL DEFAULT '1970-01-01 00:00:01',
            created_at TIMESTAMP NOT NULL DEFAULT '1970-01-01 00:00:01'
        )
EOT
        );

        $clientTableName = $this->database->applyPrefix('oidc_client');
        $this->database->write(<<< EOT
        CREATE TABLE ${clientTableName} (
            id VARCHAR(255) PRIMARY KEY NOT NULL,
            secret VARCHAR(255) NOT NULL,
            name VARCHAR(255) NOT NULL,
            description VARCHAR(255) NOT NULL,
            auth_source VARCHAR(255),
            redirect_uri TEXT NOT NULL,
            scopes TEXT NOT NULL
        )
EOT
        );

        $accessTokenTableName = $this->database->applyPrefix('oidc_access_token');
        $this->database->write(<<< EOT
        CREATE TABLE ${accessTokenTableName} (
            id VARCHAR(255) PRIMARY KEY NOT NULL,
            scopes TEXT,
            expires_at TIMESTAMP NOT NULL DEFAULT '1970-01-01 00:00:01',
            user_id VARCHAR(255) NOT NULL,                          
            client_id VARCHAR(255) NOT NULL,
            is_revoked BOOLEAN NOT NULL DEFAULT false,
            CONSTRAINT fk_access_token_user FOREIGN KEY (user_id) REFERENCES ${userTablename} (id) ON DELETE CASCADE,                                 
            CONSTRAINT fk_access_token_client FOREIGN KEY (client_id) REFERENCES ${clientTableName} (id) ON DELETE CASCADE                                
        )
EOT
        );

        $refreshTokenTableName = $this->database->applyPrefix('oidc_refresh_token');
        $this->database->write(<<< EOT
        CREATE TABLE ${refreshTokenTableName} (
            id VARCHAR(255) PRIMARY KEY NOT NULL,          
            expires_at TIMESTAMP NOT NULL DEFAULT '1970-01-01 00:00:01',
            access_token_id VARCHAR(255) NOT NULL,
            is_revoked BOOLEAN NOT NULL DEFAULT false,
            CONSTRAINT fk_refresh_token_access_token FOREIGN KEY (access_token_id) REFERENCES ${accessTokenTableName} (id) ON DELETE CASCADE
        )
EOT
        );

        $authCodeTableName = $this->database->applyPrefix('oidc_auth_code');
        $this->database->write(<<< EOT
        CREATE TABLE ${authCodeTableName} (
            id VARCHAR(255) PRIMARY KEY NOT NULL,
            scopes TEXT,
            expires_at TIMESTAMP NOT NULL DEFAULT '1970-01-01 00:00:01',
            user_id VARCHAR(255) NOT NULL,                          
            client_id VARCHAR(255) NOT NULL,
            is_revoked BOOLEAN NOT NULL DEFAULT false,
            redirect_uri TEXT NOT NULL,
            CONSTRAINT fk_auth_code_user FOREIGN KEY (user_id) REFERENCES ${userTablename} (id) ON DELETE CASCADE,                                 
            CONSTRAINT fk_auth_code_client FOREIGN KEY (client_id) REFERENCES ${clientTableName} (id) ON DELETE CASCADE                                            
        )
EOT
        );
    }
}
