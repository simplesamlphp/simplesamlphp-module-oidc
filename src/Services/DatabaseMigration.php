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

namespace SimpleSAML\Module\oidc\Services;

use PDO;
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Repositories\AuthCodeRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\IssuerStateRepository;
use SimpleSAML\Module\oidc\Repositories\PushedAuthorizationRequestRepository;
use SimpleSAML\Module\oidc\Repositories\RefreshTokenRepository;
use SimpleSAML\Module\oidc\Repositories\StatusAuditRepository;
use SimpleSAML\Module\oidc\Repositories\StatusListEntryRepository;
use SimpleSAML\Module\oidc\Repositories\StatusListRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Stores\Session\LogoutTicketStoreDb;

class DatabaseMigration
{
    /** Driver name reported for MySQL and MariaDB, the one driver needing its own DDL below. */
    private const string DRIVER_MYSQL = 'mysql';
    private const string DRIVER_SQLITE = 'sqlite';
    private const string DRIVER_PGSQL = 'pgsql';

    private readonly Database $database;

    public function __construct(?Database $database = null)
    {
        $this->database = $database ?? Database::getInstance();
    }

    public function isMigrated(): bool
    {
        return empty($this->getNotImplementedVersions());
    }

    public function getNotImplementedVersions(): array
    {
        $implementedVersions = $this->versions();
        return array_filter(get_class_methods($this), function ($method) use ($implementedVersions) {
            if (preg_match('/^version(\d+)/', $method, $matches)) {
                return !in_array($matches[1], $implementedVersions, true);
            }

            return false;
        });
    }

    public function versions(): array
    {
        $versionsTablename = $this->versionsTableName();
        $this->database->write(
            "CREATE TABLE IF NOT EXISTS $versionsTablename (version VARCHAR(191) PRIMARY KEY NOT NULL)",
        );

        return $this->database
            ->read("SELECT version FROM $versionsTablename")
            ->fetchAll(PDO::FETCH_COLUMN, 0);
    }

    public function migrate(): void
    {
        $versionsTablename = $this->versionsTableName();
        $versions = $this->versions();

        if (!in_array('20180305180300', $versions, true)) {
            $this->version20180305180300();
            $this->database->write("INSERT INTO $versionsTablename (version) VALUES ('20180305180300')");
        }

        if (!in_array('20180425203400', $versions, true)) {
            $this->version20180425203400();
            $this->database->write("INSERT INTO $versionsTablename (version) VALUES ('20180425203400')");
        }

        if (!in_array('20200517071100', $versions, true)) {
            $this->version20200517071100();
            $this->database->write("INSERT INTO $versionsTablename (version) VALUES ('20200517071100')");
        }

        if (!in_array('20200901163000', $versions, true)) {
            $this->version20200901163000();
            $this->database->write("INSERT INTO $versionsTablename (version) VALUES ('20200901163000')");
        }

        if (!in_array('20210714113000', $versions, true)) {
            $this->version20210714113000();
            $this->database->write("INSERT INTO $versionsTablename (version) VALUES ('20210714113000')");
        }

        if (!in_array('20210823141300', $versions, true)) {
            $this->version20210823141300();
            $this->database->write("INSERT INTO $versionsTablename (version) VALUES ('20210823141300')");
        }

        if (!in_array('20210827111300', $versions, true)) {
            $this->version20210827111300();
            $this->database->write("INSERT INTO $versionsTablename (version) VALUES ('20210827111300')");
        }

        if (!in_array('20210902113500', $versions, true)) {
            $this->version20210902113500();
            $this->database->write("INSERT INTO $versionsTablename (version) VALUES ('20210902113500')");
        }

        if (!in_array('20210908143500', $versions, true)) {
            $this->version20210908143500();
            $this->database->write("INSERT INTO $versionsTablename (version) VALUES ('20210908143500')");
        }

        if (!in_array('20210916153400', $versions, true)) {
            $this->version20210916153400();
            $this->database->write("INSERT INTO $versionsTablename (version) VALUES ('20210916153400')");
        }

        if (!in_array('20210916173400', $versions, true)) {
            $this->version20210916173400();
            $this->database->write("INSERT INTO $versionsTablename (version) VALUES ('20210916173400')");
        }

        if (!in_array('20240603141400', $versions, true)) {
            $this->version20240603141400();
            $this->database->write("INSERT INTO $versionsTablename (version) VALUES ('20240603141400')");
        }

        if (!in_array('20240605145700', $versions, true)) {
            $this->version20240605145700();
            $this->database->write("INSERT INTO $versionsTablename (version) VALUES ('20240605145700')");
        }

        if (!in_array('20240820132400', $versions, true)) {
            $this->version20240820132400();
            $this->database->write("INSERT INTO $versionsTablename (version) VALUES ('20240820132400')");
        }

        if (!in_array('20240828153300', $versions, true)) {
            $this->version20240828153300();
            $this->database->write("INSERT INTO $versionsTablename (version) VALUES ('20240828153300')");
        }

        if (!in_array('20240830153300', $versions, true)) {
            $this->version20240830153300();
            $this->database->write("INSERT INTO $versionsTablename (version) VALUES ('20240830153300')");
        }

        if (!in_array('20240902120000', $versions, true)) {
            $this->version20240902120000();
            $this->database->write("INSERT INTO $versionsTablename (version) VALUES ('20240902120000')");
        }

        if (!in_array('20240905120000', $versions, true)) {
            $this->version20240905120000();
            $this->database->write("INSERT INTO $versionsTablename (version) VALUES ('20240905120000')");
        }

        if (!in_array('20240906120000', $versions, true)) {
            $this->version20240906120000();
            $this->database->write("INSERT INTO $versionsTablename (version) VALUES ('20240906120000')");
        }

        if (!in_array('20250818163000', $versions, true)) {
            $this->version20250818163000();
            $this->database->write("INSERT INTO $versionsTablename (version) VALUES ('20250818163000')");
        }

        if (!in_array('20250908163000', $versions, true)) {
            $this->version20250908163000();
            $this->database->write("INSERT INTO $versionsTablename (version) VALUES ('20250908163000')");
        }

        if (!in_array('20250912163000', $versions, true)) {
            $this->version20250912163000();
            $this->database->write("INSERT INTO $versionsTablename (version) VALUES ('20250912163000')");
        }

        if (!in_array('20250913163000', $versions, true)) {
            $this->version20250913163000();
            $this->database->write("INSERT INTO $versionsTablename (version) VALUES ('20250913163000')");
        }

        if (!in_array('20250915163000', $versions, true)) {
            $this->version20250915163000();
            $this->database->write("INSERT INTO $versionsTablename (version) VALUES ('20250915163000')");
        }

        if (!in_array('20250916163000', $versions, true)) {
            $this->version20250916163000();
            $this->database->write("INSERT INTO $versionsTablename (version) VALUES ('20250916163000')");
        }

        if (!in_array('20250917163000', $versions, true)) {
            $this->version20250917163000();
            $this->database->write("INSERT INTO $versionsTablename (version) VALUES ('20250917163000')");
        }

        if (!in_array('20251021000001', $versions, true)) {
            $this->version20251021000001();
            $this->database->write("INSERT INTO $versionsTablename (version) VALUES ('20251021000001')");
        }

        if (!in_array('20251021000002', $versions, true)) {
            $this->version20251021000002();
            $this->database->write("INSERT INTO $versionsTablename (version) VALUES ('20251021000002')");
        }

        if (!in_array('20260109000001', $versions, true)) {
            $this->version20260109000001();
            $this->database->write("INSERT INTO $versionsTablename (version) VALUES ('20260109000001')");
        }

        if (!in_array('20260218163000', $versions, true)) {
            $this->version20260218163000();
            $this->database->write("INSERT INTO $versionsTablename (version) VALUES ('20260218163000')");
        }

        if (!in_array('20260608130000', $versions, true)) {
            $this->version20260608130000();
            $this->database->write("INSERT INTO $versionsTablename (version) VALUES ('20260608130000')");
        }

        if (!in_array('20260624000001', $versions, true)) {
            $this->version20260624000001();
            $this->database->write("INSERT INTO $versionsTablename (version) VALUES ('20260624000001')");
        }

        // Token Status List storage. Deliberately one table per version rather than one version for
        // all three: a version is recorded only once its whole method has succeeded, and there are no
        // transactions to undo what a method managed before it failed, so a method which creates
        // several tables would leave some of them behind and then fail again on the next run. The DDL
        // below is idempotent for the same reason.
        if (!in_array('20260801000001', $versions, true)) {
            $this->version20260801000001();
            $this->database->write("INSERT INTO $versionsTablename (version) VALUES ('20260801000001')");
        }

        if (!in_array('20260801000002', $versions, true)) {
            $this->version20260801000002();
            $this->database->write("INSERT INTO $versionsTablename (version) VALUES ('20260801000002')");
        }

        if (!in_array('20260801000003', $versions, true)) {
            $this->version20260801000003();
            $this->database->write("INSERT INTO $versionsTablename (version) VALUES ('20260801000003')");
        }

        if (!in_array('20260801000004', $versions, true)) {
            $this->version20260801000004();
            $this->database->write("INSERT INTO $versionsTablename (version) VALUES ('20260801000004')");
        }

        if (!in_array('20260801000005', $versions, true)) {
            $this->version20260801000005();
            $this->database->write("INSERT INTO $versionsTablename (version) VALUES ('20260801000005')");
        }
    }

    private function versionsTableName(): string
    {
        return $this->database->applyPrefix('oidc_migration_versions');
    }

    /**
     * @return void
     */
    private function version20180305180300(): void
    {
        $userTablename = $this->database->applyPrefix(UserRepository::TABLE_NAME);
        $this->database->write(<<< EOT
        CREATE TABLE $userTablename (
            id VARCHAR(191) PRIMARY KEY NOT NULL,
            claims TEXT,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
EOT
        ,);

        $clientTableName = $this->database->applyPrefix(ClientRepository::TABLE_NAME);
        $this->database->write(<<< EOT
        CREATE TABLE $clientTableName (
            id VARCHAR(191) PRIMARY KEY NOT NULL,
            secret VARCHAR(255) NOT NULL,
            name VARCHAR(255) NOT NULL,
            description VARCHAR(255) NOT NULL,
            auth_source VARCHAR(255),
            redirect_uri TEXT NOT NULL,
            scopes TEXT NOT NULL
        )
EOT
        ,);

        $accessTokenTableName = $this->database->applyPrefix(AccessTokenRepository::TABLE_NAME);
        $fkAccessTokenUser = $this->generateIdentifierName([$accessTokenTableName, 'user_id'], 'fk');
        $fkAccessTokenClient = $this->generateIdentifierName([$accessTokenTableName, 'client_id'], 'fk');
        $this->database->write(<<< EOT
        CREATE TABLE $accessTokenTableName (
            id VARCHAR(191) PRIMARY KEY NOT NULL,
            scopes TEXT,
            expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            user_id VARCHAR(191) NOT NULL,
            client_id VARCHAR(191) NOT NULL,
            is_revoked BOOLEAN NOT NULL DEFAULT false,
            CONSTRAINT $fkAccessTokenUser FOREIGN KEY (user_id)
                REFERENCES $userTablename (id) ON DELETE CASCADE,
            CONSTRAINT $fkAccessTokenClient FOREIGN KEY (client_id)
                REFERENCES $clientTableName (id) ON DELETE CASCADE
        )
EOT
        ,);

        $refreshTokenTableName = $this->database->applyPrefix(RefreshTokenRepository::TABLE_NAME);
        $fkRefreshTokenAccessToken = $this->generateIdentifierName([$refreshTokenTableName, 'access_token_id'], 'fk');
        $this->database->write(<<< EOT
        CREATE TABLE $refreshTokenTableName (
            id VARCHAR(191) PRIMARY KEY NOT NULL,
            expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            access_token_id VARCHAR(191) NOT NULL,
            is_revoked BOOLEAN NOT NULL DEFAULT false,
            CONSTRAINT $fkRefreshTokenAccessToken FOREIGN KEY (access_token_id)
                REFERENCES $accessTokenTableName (id) ON DELETE CASCADE
        )
EOT
        ,);

        $authCodeTableName = $this->database->applyPrefix(AuthCodeRepository::TABLE_NAME);
        $fkAuthCodeUser = $this->generateIdentifierName([$authCodeTableName, 'user_id'], 'fk');
        $fkAuthCodeClient = $this->generateIdentifierName([$authCodeTableName, 'client_id'], 'fk');
        $this->database->write(<<< EOT
        CREATE TABLE $authCodeTableName (
            id VARCHAR(191) PRIMARY KEY NOT NULL,
            scopes TEXT,
            expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            user_id VARCHAR(191) NOT NULL,
            client_id VARCHAR(191) NOT NULL,
            is_revoked BOOLEAN NOT NULL DEFAULT false,
            redirect_uri TEXT NOT NULL,
            CONSTRAINT $fkAuthCodeUser FOREIGN KEY (user_id)
                REFERENCES $userTablename (id) ON DELETE CASCADE,
            CONSTRAINT $fkAuthCodeClient FOREIGN KEY (client_id)
                REFERENCES $clientTableName (id) ON DELETE CASCADE
        )
EOT
        ,);
    }

    /**
     * @return void
     */
    private function version20180425203400(): void
    {
        $clientTableName = $this->database->applyPrefix(ClientRepository::TABLE_NAME);
        $this->database->write(<<< EOT
        ALTER TABLE {$clientTableName}
            ADD is_enabled BOOLEAN NOT NULL DEFAULT true
EOT
        ,);
    }

    private function version20200517071100(): void
    {
        $clientTableName = $this->database->applyPrefix(ClientRepository::TABLE_NAME);
        $this->database->write(<<< EOT
        ALTER TABLE {$clientTableName}
            ADD is_confidential BOOLEAN NOT NULL DEFAULT false
EOT
        ,);
    }

    private function version20200901163000(): void
    {
        $clientTableName = $this->database->applyPrefix(AuthCodeRepository::TABLE_NAME);
        $this->database->write(<<< EOT
        ALTER TABLE {$clientTableName}
            ADD nonce TEXT NULL
EOT
        ,);
    }

    private function version20210902113500(): void
    {
        $clientTableName = $this->database->applyPrefix(ClientRepository::TABLE_NAME);
        $this->database->write(<<< EOT
        ALTER TABLE {$clientTableName}
            ADD owner VARCHAR(191) NULL
EOT
        ,);
    }

    /**
     * Add auth_code_id column to access token and refresh token tables
     */
    protected function version20210714113000(): void
    {
        $tableName = $this->database->applyPrefix(AccessTokenRepository::TABLE_NAME);
        $this->database->write(<<< EOT
        ALTER TABLE {$tableName}
            ADD auth_code_id VARCHAR(191) NULL
EOT
        ,);

        $tableName = $this->database->applyPrefix(RefreshTokenRepository::TABLE_NAME);
        $this->database->write(<<< EOT
        ALTER TABLE {$tableName}
            ADD auth_code_id VARCHAR(191) NULL
EOT
        ,);
    }

    /**
     * Add requested claims to authorization token
     */
    protected function version20210823141300(): void
    {
        $tableName = $this->database->applyPrefix(AccessTokenRepository::TABLE_NAME);
        $this->database->write(<<< EOT
        ALTER TABLE {$tableName}
            ADD requested_claims TEXT NULL
EOT
        ,);
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
        CREATE TABLE $allowedOriginTableName (
            client_id VARCHAR(191) NOT NULL,
            origin VARCHAR(191) NOT NULL,
            CONSTRAINT $pkAllowedOriginClient PRIMARY KEY (client_id, origin),
            CONSTRAINT $fkAllowedOriginClient FOREIGN KEY (client_id)
                REFERENCES $clientTableName (id) ON DELETE CASCADE
        )
EOT
        ,);
    }

    /**
     * Add post_logout_redirect_uri to client.
     */
    protected function version20210908143500(): void
    {
        $clientTableName = $this->database->applyPrefix(ClientRepository::TABLE_NAME);
        $this->database->write(<<< EOT
        ALTER TABLE {$clientTableName}
            ADD post_logout_redirect_uri TEXT NULL
EOT
        ,);
    }

    /**
     * Add backchannel_logout_uri to client
     */
    protected function version20210916153400(): void
    {
        $clientTableName = $this->database->applyPrefix(ClientRepository::TABLE_NAME);
        $this->database->write(<<< EOT
        ALTER TABLE {$clientTableName}
            ADD backchannel_logout_uri TEXT NULL
EOT
        ,);
    }

    /**
     * Add logout_ticket table
     */
    protected function version20210916173400(): void
    {
        $tableName = $this->database->applyPrefix(LogoutTicketStoreDb::TABLE_NAME);
        $this->database->write(<<< EOT
        CREATE TABLE $tableName (
            sid VARCHAR(191) NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
EOT
        ,);
    }

    /**
     * Add Entity Identifier column
     */
    protected function version20240603141400(): void
    {
        $clientTableName = $this->database->applyPrefix(ClientRepository::TABLE_NAME);
        $uqEntityIdentifier = $this->generateIdentifierName([$clientTableName, 'entity_identifier'], 'uq');
        $this->database->write(<<< EOT
        ALTER TABLE {$clientTableName}
            ADD entity_identifier VARCHAR(191) NULL
EOT
        ,);

        // The syntax for adding unique constraint in existing table is different in sqlite (used in unit tests).
        if ($this->database->getDriver() !== 'mysql') {
            $this->database->write(<<< EOT
            CREATE UNIQUE INDEX $uqEntityIdentifier ON $clientTableName(entity_identifier);
EOT
            ,);
            return;
        }

        $this->database->write(<<< EOT
        ALTER TABLE {$clientTableName}
            ADD UNIQUE INDEX $uqEntityIdentifier (entity_identifier)
EOT
        ,);
    }

    /**
     * Add Client Registration Types column
     */
    protected function version20240605145700(): void
    {
        $clientTableName = $this->database->applyPrefix(ClientRepository::TABLE_NAME);
        $this->database->write(<<< EOT
        ALTER TABLE {$clientTableName}
            ADD client_registration_types VARCHAR(191) NULL
EOT
            ,);
    }

    private function version20240820132400(): void
    {
        $clientTableName = $this->database->applyPrefix(ClientRepository::TABLE_NAME);
        $this->database->write(<<< EOT
        ALTER TABLE {$clientTableName}
            ADD federation_jwks TEXT NULL
EOT
            ,);
    }

    private function version20240828153300(): void
    {
        $clientTableName = $this->database->applyPrefix(ClientRepository::TABLE_NAME);
        $this->database->write(<<< EOT
        ALTER TABLE {$clientTableName}
            ADD jwks TEXT NULL
EOT
            ,);
    }

    private function version20240830153300(): void
    {
        $clientTableName = $this->database->applyPrefix(ClientRepository::TABLE_NAME);
        $this->database->write(<<< EOT
        ALTER TABLE {$clientTableName}
            ADD jwks_uri TEXT NULL
EOT
            ,);
    }

    private function version20240902120000(): void
    {
        $clientTableName = $this->database->applyPrefix(ClientRepository::TABLE_NAME);
        $this->database->write(<<< EOT
        ALTER TABLE {$clientTableName}
            ADD signed_jwks_uri TEXT NULL
EOT
            ,);
    }

    private function version20240905120000(): void
    {
        $clientTableName = $this->database->applyPrefix(ClientRepository::TABLE_NAME);
        $idxRegistrationType = $this->generateIdentifierName([$clientTableName, 'registration_type'], 'idx');
        $idxExpiresAt = $this->generateIdentifierName([$clientTableName, 'expires_at'], 'idx');

        $this->database->write(<<< EOT
        ALTER TABLE $clientTableName ADD registration_type CHAR(32) DEFAULT 'manual';
EOT
            ,);

        $this->database->write(<<< EOT
        ALTER TABLE $clientTableName ADD updated_at TIMESTAMP NULL DEFAULT NULL;
EOT
            ,);

        $this->database->write(<<< EOT
        ALTER TABLE $clientTableName ADD created_at TIMESTAMP NULL DEFAULT NULL;
EOT
            ,);

        $this->database->write(<<< EOT
        ALTER TABLE $clientTableName ADD expires_at TIMESTAMP NULL DEFAULT NULL;
EOT
            ,);

        // The syntax for adding unique constraint in existing table is different in sqlite (used in unit tests).
        if ($this->database->getDriver() !== 'mysql') {
            $this->database->write(<<< EOT
            CREATE INDEX $idxRegistrationType ON $clientTableName(registration_type);
EOT
            ,);
            $this->database->write(<<< EOT
            CREATE INDEX $idxExpiresAt ON $clientTableName(expires_at);
EOT
            ,);
        } else {
            $this->database->write(<<< EOT
            ALTER TABLE {$clientTableName}
                ADD INDEX $idxRegistrationType (registration_type),
                ADD INDEX $idxExpiresAt (expires_at)
EOT
                ,);
        }
    }

    private function version20240906120000(): void
    {
        $clientTableName = $this->database->applyPrefix(ClientRepository::TABLE_NAME);
        $this->database->write(<<< EOT
        ALTER TABLE {$clientTableName}
            ADD is_federated BOOLEAN NOT NULL DEFAULT false
EOT
            ,);
    }

    private function version20250818163000(): void
    {
        $authCodeTableName = $this->database->applyPrefix(AuthCodeRepository::TABLE_NAME);
        $this->database->write(<<< EOT
        ALTER TABLE {$authCodeTableName}
            ADD is_pre_authorized BOOLEAN NOT NULL DEFAULT false;
EOT
            ,);
        $this->database->write(<<< EOT
        ALTER TABLE {$authCodeTableName}
            ADD tx_code VARCHAR(191) NULL;
EOT
            ,);
    }

    private function version20250908163000(): void
    {
        $issuerStateTableName = $this->database->applyPrefix(IssuerStateRepository::TABLE_NAME);
        $this->database->write(<<< EOT
        CREATE TABLE $issuerStateTableName (
            value CHAR(64) PRIMARY KEY NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            is_revoked BOOLEAN NOT NULL DEFAULT false
        )
EOT
            ,);
    }

    private function version20250912163000(): void
    {
        $authCodeTableName = $this->database->applyPrefix(AuthCodeRepository::TABLE_NAME);
        $this->database->write(<<< EOT
        ALTER TABLE {$authCodeTableName}
            DROP COLUMN is_pre_authorized;
EOT
            ,);
        $this->database->write(<<< EOT
        ALTER TABLE {$authCodeTableName}
            ADD flow_type CHAR(64) NULL;
EOT
            ,);
    }

    private function version20250913163000(): void
    {
        $authCodeTableName = $this->database->applyPrefix(AuthCodeRepository::TABLE_NAME);

        $this->database->write(<<< EOT
        ALTER TABLE {$authCodeTableName}
            ADD authorization_details TEXT NULL;
EOT
            ,);
    }

    private function version20250915163000(): void
    {
        $authCodeTableName = $this->database->applyPrefix(AuthCodeRepository::TABLE_NAME);

        $this->database->write(<<< EOT
        ALTER TABLE {$authCodeTableName}
            ADD bound_client_id TEXT NULL;
EOT
            ,);

        $clientTableName = $this->database->applyPrefix(ClientRepository::TABLE_NAME);

        $this->database->write(<<< EOT
        ALTER TABLE {$clientTableName}
            ADD is_generic BOOLEAN NOT NULL DEFAULT false;
EOT
            ,);
    }

    private function version20250916163000(): void
    {
        $authCodeTableName = $this->database->applyPrefix(AuthCodeRepository::TABLE_NAME);

        $this->database->write(<<< EOT
        ALTER TABLE {$authCodeTableName}
            ADD bound_redirect_uri TEXT NULL;
EOT
            ,);
    }

    private function version20250917163000(): void
    {
        $accessTokenTableName = $this->database->applyPrefix(AccessTokenRepository::TABLE_NAME);

        $this->database->write(<<< EOT
        ALTER TABLE {$accessTokenTableName}
            ADD flow_type CHAR(64) NULL;
EOT
            ,);
        $this->database->write(<<< EOT
        ALTER TABLE {$accessTokenTableName}
            ADD authorization_details TEXT NULL;
EOT
            ,);
        $this->database->write(<<< EOT
        ALTER TABLE {$accessTokenTableName}
            ADD bound_client_id TEXT NULL;
EOT
            ,);
        $this->database->write(<<< EOT
        ALTER TABLE {$accessTokenTableName}
            ADD bound_redirect_uri TEXT NULL;
EOT
            ,);
    }

    private function version20251021000001(): void
    {
        $authCodeTableName = $this->database->applyPrefix(AuthCodeRepository::TABLE_NAME);
        $this->database->write(<<< EOT
        ALTER TABLE {$authCodeTableName}
            ADD issuer_state TEXT NULL
EOT
        ,);
    }

    private function version20251021000002(): void
    {
        $accessTokenTableName = $this->database->applyPrefix(AccessTokenRepository::TABLE_NAME);
        $this->database->write(<<< EOT
        ALTER TABLE {$accessTokenTableName}
            ADD issuer_state TEXT NULL
EOT
        ,);
    }

    private function version20260109000001(): void
    {
        $clientTableName = $this->database->applyPrefix(ClientRepository::TABLE_NAME);
        $this->database->write(<<< EOT
        ALTER TABLE {$clientTableName}
            ADD extra_metadata TEXT NULL
EOT
            ,);
    }


    private function version20260218163000(): void
    {
        $clientTableName = $this->database->applyPrefix(ClientRepository::TABLE_NAME);
        $this->database->write(<<< EOT
        ALTER TABLE {$clientTableName}
            DROP COLUMN is_federated;
EOT
            ,);
    }


    private function version20260608130000(): void
    {
        $parTableName = $this->database->applyPrefix(PushedAuthorizationRequestRepository::TABLE_NAME);
        $clientTableName = $this->database->applyPrefix(ClientRepository::TABLE_NAME);
        $fkParClient = $this->generateIdentifierName([$parTableName, 'client_id'], 'fk');
        $idxParExpiresAt = $this->generateIdentifierName([$parTableName, 'expires_at'], 'idx');

        // request_uri is always a fixed-length value: REQUEST_URI_PREFIX (34 chars) +
        // bin2hex(random_bytes(32)) (64 chars) = 98 chars. See PushedAuthorizationRequestEntityFactory::fromData().
        $this->database->write(<<< EOT
        CREATE TABLE $parTableName (
            request_uri CHAR(98) PRIMARY KEY NOT NULL,
            client_id VARCHAR(191) NOT NULL,
            parameters TEXT NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            is_consumed BOOLEAN NOT NULL DEFAULT false,
            CONSTRAINT $fkParClient FOREIGN KEY (client_id)
                REFERENCES $clientTableName (id) ON DELETE CASCADE
        )
EOT
        ,);

        $this->database->write("CREATE INDEX $idxParExpiresAt ON $parTableName (expires_at)");
    }

    /**
     * Add storage for the OpenID Connect Dynamic Client Registration Access Token (a hash of it), used to
     * authenticate read requests at the Client Configuration Endpoint.
     */
    private function version20260624000001(): void
    {
        $clientTableName = $this->database->applyPrefix(ClientRepository::TABLE_NAME);
        $this->database->write(<<< EOT
        ALTER TABLE {$clientTableName}
            ADD registration_access_token VARCHAR(255) NULL
EOT
            ,);
    }


    /**
     * Create the Status List table.
     *
     * Everything the pool configured is stored on the row rather than looked up at use time. A list has
     * to keep being served exactly as the credentials pointing at it were issued against, so changing
     * a pool's settings routes new credentials to new lists and leaves existing ones alone.
     */
    private function version20260801000001(): void
    {
        $statusListTableName = $this->database->applyPrefix(StatusListRepository::TABLE_NAME);
        $uqPoolGeneration = $this->generateIdentifierName([$statusListTableName, 'pool_generation'], 'uq');
        $ckBits = $this->generateIdentifierName([$statusListTableName, 'bits'], 'ck');
        $ckCapacity = $this->generateIdentifierName([$statusListTableName, 'capacity'], 'ck');
        $idxAllocationCandidates = $this->generateIdentifierName(
            [$statusListTableName, 'allocation_candidates'],
            'idx',
        );

        $dateTime = $this->dateTimeColumnType();
        // Worst case, at 8 bits per entry and the default capacity, the signed token runs to some
        // 233 KB: the byte array is 128 KiB, its base64url form around 175 KB, and the JWT payload is
        // that JSON base64url encoded a second time. MySQL's TEXT tops out at 64 KB, so it needs
        // MEDIUMTEXT; the other drivers have no such limit.
        $largeText = $this->largeTextColumnType();

        // Every fixed length looking column here is VARCHAR rather than CHAR, deliberately. These hold
        // values produced by application code and then compared for equality, and PostgreSQL blank-pads
        // CHAR and keeps the padding on the way out. A value even one character short would come back
        // padded and never compare equal to itself again -- silently, and only on PostgreSQL.
        $this->database->write(<<< EOT
        CREATE TABLE IF NOT EXISTS $statusListTableName (
            id VARCHAR(64) PRIMARY KEY NOT NULL,
            uri TEXT NOT NULL,
            pool_id VARCHAR(191) NOT NULL,
            policy_fingerprint VARCHAR(64) NOT NULL,
            generation INT NOT NULL,
            bits SMALLINT NOT NULL,
            capacity INT NOT NULL,
            allowed_statuses VARCHAR(64) NOT NULL,
            ttl_seconds INT NOT NULL,
            token_validity_seconds INT NOT NULL,
            refresh_interval_seconds INT NOT NULL,
            signing_key_id TEXT NOT NULL,
            key_profile VARCHAR(32) NOT NULL,
            allocated_count INT NOT NULL DEFAULT 0,
            is_active BOOLEAN NOT NULL DEFAULT true,
            deactivated_at $dateTime NULL,
            retired_at $dateTime NULL,
            signed_token $largeText NULL,
            -- VARCHAR rather than CHAR because this column is the one place a fixed width would not
            -- hold: it carries either a 64 character hash or the empty string meaning nothing is
            -- published. PostgreSQL blank-pads CHAR and keeps the padding on the way out, so an empty
            -- string would read back as 64 spaces and never compare equal to '' again, which would
            -- make the compare-and-set that publishes a token match no rows for ever.
            signed_token_content_hash VARCHAR(64) NOT NULL DEFAULT '',
            signed_token_iat $dateTime NULL,
            signed_token_exp $dateTime NULL,
            created_at $dateTime NOT NULL,
            CONSTRAINT $uqPoolGeneration UNIQUE (pool_id, generation),
            CONSTRAINT $ckBits CHECK (bits IN (1, 2, 4, 8)),
            CONSTRAINT $ckCapacity CHECK (capacity > 0)
        )
EOT
        ,);

        // Allocation asks for the active lists of one pool whose policy matches the current one, so
        // all three columns are in the index, in that order.
        $this->createIndex(
            $idxAllocationCandidates,
            $statusListTableName,
            'pool_id, is_active, policy_fingerprint',
        );
    }

    /**
     * Create the Status List entry table.
     *
     * Every index of a list exists as a row from the moment the list is created, which is what lets an
     * index be claimed by an UPDATE that matches only while it is free. The affected row count then
     * answers "did I get it", with no need to tell a unique constraint violation apart from any other
     * database error, which this module can not do reliably.
     */
    private function version20260801000002(): void
    {
        $statusListTableName = $this->database->applyPrefix(StatusListRepository::TABLE_NAME);
        $entryTableName = $this->database->applyPrefix(StatusListEntryRepository::TABLE_NAME);

        $fkEntryStatusList = $this->generateIdentifierName([$entryTableName, 'status_list_id'], 'fk');
        $ckStatus = $this->generateIdentifierName([$entryTableName, 'status'], 'ck');
        $ckIdx = $this->generateIdentifierName([$entryTableName, 'idx'], 'ck');
        $uqCredentialIdHash = $this->generateIdentifierName([$entryTableName, 'credential_id_hash'], 'uq');
        $idxReconstruction = $this->generateIdentifierName([$entryTableName, 'reconstruction'], 'idx');
        $idxExpiresAt = $this->generateIdentifierName([$entryTableName, 'expires_at'], 'idx');
        $idxListExpiresAt = $this->generateIdentifierName([$entryTableName, 'list_expires_at'], 'idx');

        $dateTime = $this->dateTimeColumnType();

        // The credential ID is a URI, so it has no length this schema could safely assume; lookups go
        // through its hash, which does. Note that expires_at being NULL is meaningful: it marks a
        // credential which never expires, and a list holding one can never be retired.
        $this->database->write(<<< EOT
        CREATE TABLE IF NOT EXISTS $entryTableName (
            status_list_id VARCHAR(64) NOT NULL,
            idx INT NOT NULL,
            allocated BOOLEAN NOT NULL DEFAULT false,
            status SMALLINT NOT NULL DEFAULT 0,
            expires_at $dateTime NULL,
            credential_id TEXT NULL,
            credential_id_hash VARCHAR(64) NULL,
            credential_configuration_id VARCHAR(191) NULL,
            subject_ref VARCHAR(64) NULL,
            issued_at $dateTime NULL,
            updated_at $dateTime NULL,
            PRIMARY KEY (status_list_id, idx),
            CONSTRAINT $fkEntryStatusList FOREIGN KEY (status_list_id)
                REFERENCES $statusListTableName (id) ON DELETE CASCADE,
            CONSTRAINT $ckStatus CHECK (status >= 0),
            CONSTRAINT $ckIdx CHECK (idx >= 0)
        )
EOT
        ,);

        // Unallocated rows leave this null, and every driver here allows repeated nulls in a unique
        // index, so the constraint applies to the allocated rows only, which is what is wanted.
        $this->createIndex($uqCredentialIdHash, $entryTableName, 'credential_id_hash', true);

        // Rebuilding a list reads the entries which are not Valid, in index order. Carrying idx in the
        // index as well makes that query answerable from the index alone.
        $this->createIndex($idxReconstruction, $entryTableName, 'status_list_id, status, idx');

        // Deleting the linkage of credentials which have expired, across all lists.
        $this->createIndex($idxExpiresAt, $entryTableName, 'expires_at');

        // Deciding whether one list has any entry left which keeps it from being retired.
        $this->createIndex($idxListExpiresAt, $entryTableName, 'status_list_id, expires_at');
    }

    /**
     * Create the Status List audit table.
     *
     * Deliberately without a foreign key to the Status List table: the trail records what was done and
     * has its own retention, so it must not be cascaded away when a list is eventually removed. Only
     * the hash of a credential ID is kept, so the trail does not outlive the linkage which is dropped
     * when a credential expires.
     */
    private function version20260801000003(): void
    {
        $auditTableName = $this->database->applyPrefix(StatusAuditRepository::TABLE_NAME);
        $idxCreatedAt = $this->generateIdentifierName([$auditTableName, 'created_at'], 'idx');
        $idxCredentialIdHash = $this->generateIdentifierName([$auditTableName, 'credential_id_hash'], 'idx');

        $dateTime = $this->dateTimeColumnType();

        $this->database->write(<<< EOT
        CREATE TABLE IF NOT EXISTS $auditTableName (
            id VARCHAR(191) PRIMARY KEY NOT NULL,
            credential_id_hash VARCHAR(64) NOT NULL,
            status_list_id VARCHAR(64) NOT NULL,
            idx INT NOT NULL,
            old_status SMALLINT NOT NULL,
            new_status SMALLINT NOT NULL,
            actor_ref VARCHAR(191) NULL,
            source VARCHAR(16) NOT NULL,
            created_at $dateTime NOT NULL
        )
EOT
        ,);

        $this->createIndex($idxCreatedAt, $auditTableName, 'created_at');
        $this->createIndex($idxCredentialIdHash, $auditTableName, 'credential_id_hash');
    }

    /**
     * Count of how many times a Status List's published token has been invalidated.
     *
     * The content hash alone cannot settle publication. Its "nothing is published" value is the empty
     * string, and an invalidation which finds it already empty leaves it empty -- so a signer which
     * observed the empty string still matches afterwards and publishes a token built before that
     * invalidation. Since the invalidating writer has already finished, nothing clears it again, and a
     * revoked credential reads as valid until the refresh interval elapses or the reconciler runs.
     *
     * A counter which every invalidation increments always changes, so a signer which observed the
     * earlier value no longer matches and rebuilds instead.
     *
     * The existence check is what makes this re-runnable. Being a single statement is not enough: the
     * version is recorded by a *separate* statement afterwards, so a process which dies in between
     * leaves the column added and the version still pending, and every later migration run would fail
     * on a duplicate column until somebody repaired the schema by hand.
     */
    private function version20260801000004(): void
    {
        $statusListTableName = $this->database->applyPrefix(StatusListRepository::TABLE_NAME);

        if ($this->hasColumn($statusListTableName, 'invalidation_counter')) {
            return;
        }

        $this->database->write(<<< EOT
        ALTER TABLE {$statusListTableName}
            ADD invalidation_counter INT NOT NULL DEFAULT 0
EOT
            ,);
    }

    /**
     * Indexes the administration screens read Status List entries by.
     *
     * Both answer questions no other caller asks. Everything else addresses an entry by its list and
     * index, or by the hash of one credential ID; an administrator arrives with neither, and has to be
     * able to page through what was issued and to find every credential belonging to one person.
     */
    private function version20260801000005(): void
    {
        $entryTableName = $this->database->applyPrefix(StatusListEntryRepository::TABLE_NAME);

        // Paging through issued credentials, newest first. Allocation leads, because the unallocated
        // rows are the bulk of the table and are never listed; the timestamp follows so the ordering
        // comes out of the index rather than out of a sort over everything it selected.
        $this->createIndex(
            $this->generateIdentifierName([$entryTableName, 'allocated_issued_at'], 'idx'),
            $entryTableName,
            'allocated, issued_at',
        );

        // Every credential issued to one subject, which is how a lost device or a departing member of
        // staff is dealt with. The stored value is a keyed hash, so this is an equality lookup on a
        // value the administrator never sees and the search box derives.
        $this->createIndex(
            $this->generateIdentifierName([$entryTableName, 'subject_ref'], 'idx'),
            $entryTableName,
            'subject_ref',
        );
    }

    /**
     * Whether a table already has a column.
     *
     * None of the three drivers offers ADD COLUMN IF NOT EXISTS across the board -- PostgreSQL does,
     * MySQL and SQLite do not -- so the catalog is consulted instead. MySQL and PostgreSQL both expose
     * information_schema; SQLite has its own table of table definitions.
     */
    private function hasColumn(string $tableName, string $columnName): bool
    {
        if ($this->database->getDriver() === self::DRIVER_SQLITE) {
            // The pragma cannot take a bound parameter, and the name here is assembled from a constant
            // and the configured prefix rather than from anything a request supplies.
            $statement = sprintf('SELECT 1 FROM pragma_table_info(%s) WHERE name = :columnName', "'$tableName'");
            $params = ['columnName' => $columnName];
        } else {
            $isPostgres = $this->database->getDriver() === self::DRIVER_PGSQL;

            // Restricted to the database being migrated: MySQL's information_schema spans every schema
            // on the server, so an unrestricted lookup could find a like-named column elsewhere.
            $schemaFunction = $isPostgres ? 'CURRENT_SCHEMA()' : 'DATABASE()';
            $statement = 'SELECT 1 FROM information_schema.columns ' .
            "WHERE table_schema = $schemaFunction AND table_name = :tableName AND column_name = :columnName";

            // PostgreSQL folds unquoted identifiers to lower case, and nothing here quotes them, so a
            // table created from a prefix with any upper case in it is stored lower cased. Comparing
            // the name as configured would find nothing, conclude the column is missing, and turn a
            // retry into the duplicate column error this check exists to prevent. MySQL keeps the case
            // it was given, so its names are compared as they are.
            $params = $isPostgres ?
            ['tableName' => strtolower($tableName), 'columnName' => strtolower($columnName)] :
            ['tableName' => $tableName, 'columnName' => $columnName];
        }

        // Every statement around this writes to the primary, so asking a secondary whether the column
        // is there can get a stale no and turn a retry into the duplicate column error this exists to
        // avoid. Migrations run on hosts which may predate the primary read, so it is used only where
        // it is available.
        $existing = ModuleConfig::hasPrimaryDatabaseReadCapability() ?
        $this->database->readPrimary($statement, $params)->fetchAll() :
        $this->database->read($statement, $params)->fetchAll();

        return $existing !== [];
    }

    /**
     * Column type for a value which can reach a few hundred kilobytes.
     *
     * MySQL's TEXT holds 64 KB, which a Status List Token can exceed, so it needs the next size up.
     * PostgreSQL and SQLite place no such limit on TEXT.
     */
    private function largeTextColumnType(): string
    {
        return $this->database->getDriver() === self::DRIVER_MYSQL ? 'MEDIUMTEXT' : 'TEXT';
    }

    /**
     * Column type for a point in time.
     *
     * MySQL's TIMESTAMP only spans 1970 to 2038, which a credential expiry can legitimately outlive, so
     * DATETIME is used there. PostgreSQL has no DATETIME, and SQLite stores whatever it is given.
     */
    private function dateTimeColumnType(): string
    {
        return $this->database->getDriver() === self::DRIVER_MYSQL ? 'DATETIME' : 'TIMESTAMP';
    }

    /**
     * Create an index unless it is already there.
     *
     * PostgreSQL and SQLite say so directly. MySQL has no IF NOT EXISTS for CREATE INDEX, so its
     * catalog is consulted first. Being able to re-run this is what makes a version method safe to
     * retry after it failed partway through, which it can: a version is recorded only once the whole
     * method succeeded, and nothing rolls back what it managed before that.
     */
    private function createIndex(
        string $indexName,
        string $tableName,
        string $columns,
        bool $isUnique = false,
    ): void {
        $unique = $isUnique ? 'UNIQUE ' : '';

        if ($this->database->getDriver() !== self::DRIVER_MYSQL) {
            $this->database->write(
                "CREATE {$unique}INDEX IF NOT EXISTS $indexName ON $tableName ($columns)",
            );

            return;
        }

        $statement = 'SELECT 1 FROM information_schema.statistics ' .
        'WHERE table_schema = DATABASE() AND table_name = :tableName AND index_name = :indexName';
        $params = ['tableName' => $tableName, 'indexName' => $indexName];

        // Every statement above writes to the primary, so asking a secondary whether the index is
        // there can get a stale no and turn this retry into a duplicate index error on the primary,
        // which is exactly what the check exists to avoid. Migrations run on every deployment,
        // including hosts predating the primary read, so it is used only where it is available.
        $existing = ModuleConfig::hasPrimaryDatabaseReadCapability() ?
        $this->database->readPrimary($statement, $params)->fetchAll() :
        $this->database->read($statement, $params)->fetchAll();

        if ($existing !== []) {
            return;
        }

        $this->database->write("CREATE {$unique}INDEX $indexName ON $tableName ($columns)");
    }

    /**
     * @param string[] $columnNames
     */
    private function generateIdentifierName(array $columnNames, string $prefix = '', int $maxSize = 30): string
    {
        $hash = implode('', array_map(fn($column) => dechex(crc32($column)), $columnNames));

        return mb_strtoupper(mb_substr("{$prefix}_$hash", 0, $maxSize));
    }
}
