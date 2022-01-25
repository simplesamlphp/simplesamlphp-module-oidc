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

namespace SimpleSAML\Module\oidc\Services;

use PDO;
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Repositories\AuthCodeRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\RefreshTokenRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Store\SessionLogoutTicketStoreDb;

class DatabaseMigration
{
    private Database $database;

    public function __construct(Database $database = null)
    {
        $this->database = $database ?? Database::getInstance();
    }

    public function isUpdated(): bool
    {
        $implementedVersions = $this->versions();
        $notImplementedVersions = array_filter(get_class_methods($this), function ($method) use ($implementedVersions) {
            if (preg_match('/^version(\d+)/', $method, $matches)) {
                return !in_array($matches[1], $implementedVersions, true);
            }

            return false;
        });

        return empty($notImplementedVersions);
    }

    public function versions(): array
    {
        $versionsTablename = $this->versionsTableName();
        $this->database->write(
            "CREATE TABLE IF NOT EXISTS {$versionsTablename} (version VARCHAR(191) PRIMARY KEY NOT NULL)"
        );

        return $this->database
            ->read("SELECT version FROM ${versionsTablename}")
            ->fetchAll(PDO::FETCH_COLUMN, 0);
    }

    public function migrate(): void
    {
        $versionsTablename = $this->versionsTableName();
        $versions = $this->versions();

        if (!in_array('20180305180300', $versions, true)) {
            $this->version20180305180300();
            $this->database->write("INSERT INTO ${versionsTablename} (version) VALUES ('20180305180300')");
        }

        if (!in_array('20180425203400', $versions, true)) {
            $this->version20180425203400();
            $this->database->write("INSERT INTO ${versionsTablename} (version) VALUES ('20180425203400')");
        }

        if (!in_array('20200517071100', $versions, true)) {
            $this->version20200517071100();
            $this->database->write("INSERT INTO ${versionsTablename} (version) VALUES ('20200517071100')");
        }

        if (!in_array('20200901163000', $versions, true)) {
            $this->version20200901163000();
            $this->database->write("INSERT INTO ${versionsTablename} (version) VALUES ('20200901163000')");
        }

        if (!in_array('20210714113000', $versions, true)) {
            $this->version20210714113000();
            $this->database->write("INSERT INTO ${versionsTablename} (version) VALUES ('20210714113000')");
        }

        if (!in_array('20210823141300', $versions, true)) {
            $this->version20210823141300();
            $this->database->write("INSERT INTO ${versionsTablename} (version) VALUES ('20210823141300')");
        }

        if (!in_array('20210827111300', $versions, true)) {
            $this->version20210827111300();
            $this->database->write("INSERT INTO ${versionsTablename} (version) VALUES ('20210827111300')");
        }

        if (!in_array('20210902113500', $versions, true)) {
            $this->version20210902113500();
            $this->database->write("INSERT INTO ${versionsTablename} (version) VALUES ('20210902113500')");
        }

        if (!in_array('20210908143500', $versions, true)) {
            $this->version20210908143500();
            $this->database->write("INSERT INTO ${versionsTablename} (version) VALUES ('20210908143500')");
        }

        if (!in_array('20210916153400', $versions, true)) {
            $this->version20210916153400();
            $this->database->write("INSERT INTO ${versionsTablename} (version) VALUES ('20210916153400')");
        }

        if (!in_array('20210916173400', $versions, true)) {
            $this->version20210916173400();
            $this->database->write("INSERT INTO ${versionsTablename} (version) VALUES ('20210916173400')");
        }
    }

    private function versionsTableName(): string
    {
        return $this->database->applyPrefix('oidc_migration_versions');
    }

    /**
     * @return void
     */
    private function version20180305180300()
    {
        $userTablename = $this->database->applyPrefix(UserRepository::TABLE_NAME);
        $this->database->write(<<< EOT
        CREATE TABLE ${userTablename} (
            id VARCHAR(191) PRIMARY KEY NOT NULL,
            claims TEXT,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
EOT
        );

        $clientTableName = $this->database->applyPrefix(ClientRepository::TABLE_NAME);
        $this->database->write(<<< EOT
        CREATE TABLE ${clientTableName} (
            id VARCHAR(191) PRIMARY KEY NOT NULL,
            secret VARCHAR(255) NOT NULL,
            name VARCHAR(255) NOT NULL,
            description VARCHAR(255) NOT NULL,
            auth_source VARCHAR(255),
            redirect_uri TEXT NOT NULL,
            scopes TEXT NOT NULL
        )
EOT
        );

        $accessTokenTableName = $this->database->applyPrefix(AccessTokenRepository::TABLE_NAME);
        $fkAccessTokenUser = $this->generateIdentifierName([$accessTokenTableName, 'user_id'], 'fk');
        $fkAccessTokenClient = $this->generateIdentifierName([$accessTokenTableName, 'client_id'], 'fk');
        $this->database->write(<<< EOT
        CREATE TABLE ${accessTokenTableName} (
            id VARCHAR(191) PRIMARY KEY NOT NULL,
            scopes TEXT,
            expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            user_id VARCHAR(191) NOT NULL,                          
            client_id VARCHAR(191) NOT NULL,
            is_revoked BOOLEAN NOT NULL DEFAULT false,
            CONSTRAINT {$fkAccessTokenUser} FOREIGN KEY (user_id) 
                REFERENCES ${userTablename} (id) ON DELETE CASCADE,                                 
            CONSTRAINT {$fkAccessTokenClient} FOREIGN KEY (client_id) 
                REFERENCES ${clientTableName} (id) ON DELETE CASCADE                                
        )
EOT
        );

        $refreshTokenTableName = $this->database->applyPrefix(RefreshTokenRepository::TABLE_NAME);
        $fkRefreshTokenAccessToken = $this->generateIdentifierName([$refreshTokenTableName, 'access_token_id'], 'fk');
        $this->database->write(<<< EOT
        CREATE TABLE ${refreshTokenTableName} (
            id VARCHAR(191) PRIMARY KEY NOT NULL,          
            expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            access_token_id VARCHAR(191) NOT NULL,
            is_revoked BOOLEAN NOT NULL DEFAULT false,
            CONSTRAINT {$fkRefreshTokenAccessToken} FOREIGN KEY (access_token_id)
                REFERENCES ${accessTokenTableName} (id) ON DELETE CASCADE
        )
EOT
        );

        $authCodeTableName = $this->database->applyPrefix(AuthCodeRepository::TABLE_NAME);
        $fkAuthCodeUser = $this->generateIdentifierName([$authCodeTableName, 'user_id'], 'fk');
        $fkAuthCodeClient = $this->generateIdentifierName([$authCodeTableName, 'client_id'], 'fk');
        $this->database->write(<<< EOT
        CREATE TABLE ${authCodeTableName} (
            id VARCHAR(191) PRIMARY KEY NOT NULL,
            scopes TEXT,
            expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            user_id VARCHAR(191) NOT NULL,                          
            client_id VARCHAR(191) NOT NULL,
            is_revoked BOOLEAN NOT NULL DEFAULT false,
            redirect_uri TEXT NOT NULL,
            CONSTRAINT {$fkAuthCodeUser} FOREIGN KEY (user_id)
                REFERENCES ${userTablename} (id) ON DELETE CASCADE,                                 
            CONSTRAINT {$fkAuthCodeClient} FOREIGN KEY (client_id)
                REFERENCES ${clientTableName} (id) ON DELETE CASCADE                                            
        )
EOT
        );
    }

    /**
     * @return void
     */
    private function version20180425203400()
    {
        $clientTableName = $this->database->applyPrefix(ClientRepository::TABLE_NAME);
        $this->database->write(<<< EOT
        ALTER TABLE ${clientTableName}
            ADD is_enabled BOOLEAN NOT NULL DEFAULT true
EOT
        );
    }

    private function version20200517071100()
    {
        $clientTableName = $this->database->applyPrefix(ClientRepository::TABLE_NAME);
        $this->database->write(<<< EOT
        ALTER TABLE ${clientTableName}
            ADD is_confidential BOOLEAN NOT NULL DEFAULT false 
EOT
        );
    }

    private function version20200901163000(): void
    {
        $clientTableName = $this->database->applyPrefix(AuthCodeRepository::TABLE_NAME);
        $this->database->write(<<< EOT
        ALTER TABLE ${clientTableName}
            ADD nonce TEXT NULL 
EOT
        );
    }

    private function version20210902113500(): void
    {
        $clientTableName = $this->database->applyPrefix(ClientRepository::TABLE_NAME);
        $this->database->write(<<< EOT
        ALTER TABLE ${clientTableName}
            ADD owner VARCHAR(191) NULL 
EOT
        );
    }

    /**
     * Add auth_code_id column to access token and refresh token tables
     */
    protected function version20210714113000()
    {
        $tableName = $this->database->applyPrefix(AccessTokenRepository::TABLE_NAME);
        $this->database->write(<<< EOT
        ALTER TABLE ${tableName}
            ADD auth_code_id VARCHAR(191) NULL 
EOT
        );

        $tableName = $this->database->applyPrefix(RefreshTokenRepository::TABLE_NAME);
        $this->database->write(<<< EOT
        ALTER TABLE ${tableName}
            ADD auth_code_id VARCHAR(191) NULL 
EOT
        );
    }

    /**
     * Add requested claims to authorization token
     */
    protected function version20210823141300()
    {
        $tableName = $this->database->applyPrefix(AccessTokenRepository::TABLE_NAME);
        $this->database->write(<<< EOT
        ALTER TABLE ${tableName}
            ADD requested_claims TEXT NULL 
EOT
        );
    }

    /**
     * Add table for allowed origins.
     */
    protected function version20210827111300(): void
    {
        $allowedOriginTableName = $this->database->applyPrefix(AllowedOriginRepository::TABLE_NAME);
        $clientTableName = $this->database->applyPrefix(ClientRepository::TABLE_NAME);
        $pkAllowedOriginClient = $this->generateIdentifierName([$allowedOriginTableName, 'client_id', 'origin'], 'pk');
        $fkAllowedOriginClient = $this->generateIdentifierName([$allowedOriginTableName, 'client_id'], 'fk');

        $this->database->write(<<< EOT
        CREATE TABLE ${allowedOriginTableName} (
            client_id VARCHAR(191) NOT NULL,
            origin VARCHAR(191) NOT NULL,
            CONSTRAINT {$pkAllowedOriginClient} PRIMARY KEY (client_id, origin),
            CONSTRAINT {$fkAllowedOriginClient} FOREIGN KEY (client_id)
                REFERENCES ${clientTableName} (id) ON DELETE CASCADE
        )
EOT
        );
    }

    /**
     * Add post_logout_redirect_uri to client.
     */
    protected function version20210908143500(): void
    {
        $clientTableName = $this->database->applyPrefix(ClientRepository::TABLE_NAME);
        $this->database->write(<<< EOT
        ALTER TABLE ${clientTableName}
            ADD post_logout_redirect_uri TEXT NULL 
EOT
        );
    }

    /**
     * Add backchannel_logout_uri to client
     */
    protected function version20210916153400()
    {
        $clientTableName = $this->database->applyPrefix(ClientRepository::TABLE_NAME);
        $this->database->write(<<< EOT
        ALTER TABLE ${clientTableName}
            ADD backchannel_logout_uri TEXT NULL 
EOT
        );
    }

    /**
     * Add logout_ticket table
     */
    protected function version20210916173400()
    {
        $tableName = $this->database->applyPrefix(SessionLogoutTicketStoreDb::TABLE_NAME);
        $this->database->write(
            <<< EOT
        CREATE TABLE ${tableName} (
            sid VARCHAR(191) NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
EOT
        );
    }

    private function generateIdentifierName(array $columnNames, string $prefix = '', int $maxSize = 30): string
    {
        $hash = implode('', array_map(function ($column) {
            return dechex(crc32($column));
        }, $columnNames));

        return mb_strtoupper(mb_substr("{$prefix}_{$hash}", 0, $maxSize));
    }
}
