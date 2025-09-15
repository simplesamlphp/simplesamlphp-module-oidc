PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE oidc_migration_versions (version VARCHAR(191) PRIMARY KEY NOT NULL);
INSERT INTO oidc_migration_versions VALUES('20180305180300');
INSERT INTO oidc_migration_versions VALUES('20180425203400');
INSERT INTO oidc_migration_versions VALUES('20200517071100');
INSERT INTO oidc_migration_versions VALUES('20200901163000');
INSERT INTO oidc_migration_versions VALUES('20210714113000');
INSERT INTO oidc_migration_versions VALUES('20210823141300');
INSERT INTO oidc_migration_versions VALUES('20210827111300');
INSERT INTO oidc_migration_versions VALUES('20210902113500');
INSERT INTO oidc_migration_versions VALUES('20210908143500');
INSERT INTO oidc_migration_versions VALUES('20210916153400');
INSERT INTO oidc_migration_versions VALUES('20210916173400');
INSERT INTO oidc_migration_versions VALUES('20240603141400');
INSERT INTO oidc_migration_versions VALUES('20240605145700');
CREATE TABLE oidc_user (
            id VARCHAR(191) PRIMARY KEY NOT NULL,
            claims TEXT,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
CREATE TABLE oidc_client (
            id VARCHAR(191) PRIMARY KEY NOT NULL,
            secret VARCHAR(255) NOT NULL,
            name VARCHAR(255) NOT NULL,
            description VARCHAR(255) NOT NULL,
            auth_source VARCHAR(255),
            redirect_uri TEXT NOT NULL,
            scopes TEXT NOT NULL,
            is_enabled BOOLEAN NOT NULL DEFAULT true,
            is_confidential BOOLEAN NOT NULL DEFAULT false,
            owner VARCHAR(191) NULL,
            post_logout_redirect_uri TEXT NULL,
            backchannel_logout_uri TEXT NULL,
            entity_identifier VARCHAR(255) NULL,
            client_registration_types VARCHAR(255) NULL,
            federation_jwks TEXT NULL,
            jwks TEXT NULL,
            jwks_uri TEXT NULL,
            signed_jwks_uri TEXT NULL,
            registration_type CHAR(32) DEFAULT 'manual',
            updated_at TIMESTAMP NULL DEFAULT NULL,
            created_at TIMESTAMP NULL DEFAULT NULL,
            expires_at TIMESTAMP NULL DEFAULT NULL,
            is_federated BOOLEAN NOT NULL DEFAULT false,
            is_generic BOOLEAN NOT NULL DEFAULT false
);
-- Used 'httpd' host for back-channel logout url (https://httpd:8443/test/a/simplesamlphp-module-oidc/backchannel_logout)
-- since this is the hostname of conformance server while running in container environment
INSERT INTO oidc_client VALUES('_55a99a1d298da921cb27d700d4604352e51171ebc4','_8967dd97d07cc59db7055e84ac00e79005157c1132','Conformance Client 1',replace('Client 1 for Conformance Testing  https://openid.net/certification/connect_op_testing/\n','\n',char(10)),'example-userpass','["https:\/\/localhost.emobix.co.uk:8443\/test\/a\/simplesamlphp-module-oidc\/callback","https:\/\/www.certification.openid.net\/test\/a\/simplesamlphp-module-oidc\/callback"]','["openid","profile","email","address","phone","offline_access"]',1,1,NULL,'["https:\/\/localhost.emobix.co.uk:8443\/test\/a\/simplesamlphp-module-oidc\/post_logout_redirect"]','https://httpd:8443/test/a/simplesamlphp-module-oidc/backchannel_logout',NULL,NULL, NULL, NULL, NULL, NULL, 'manual', NULL, NULL, NULL, false, false);
INSERT INTO oidc_client VALUES('_34efb61060172a11d62101bc804db789f8f9100b0e','_91a4607a1c10ba801268929b961b3f6c067ff82d21','Conformance Client 2','','example-userpass','["https:\/\/localhost.emobix.co.uk:8443\/test\/a\/simplesamlphp-module-oidc\/callback","https:\/\/www.certification.openid.net\/test\/a\/simplesamlphp-module-oidc\/callback"]','["openid","profile","email","offline_access"]',1,1,NULL,NULL,NULL,NULL,NULL, NULL, NULL, NULL, NULL, 'manual', NULL, NULL, NULL, false, false);
INSERT INTO oidc_client VALUES('_0afb7d18e54b2de8205a93e38ca119e62ee321d031','_944e73bbeec7850d32b68f1b5c780562c955967e4e','Conformance Client 3','Client for client_secret_post','example-userpass','["https:\/\/localhost.emobix.co.uk:8443\/test\/a\/simplesamlphp-module-oidc\/callback","https:\/\/www.certification.openid.net\/test\/a\/simplesamlphp-module-oidc\/callback"]','["openid","profile","email"]',1,1,NULL,NULL,NULL,NULL,NULL, NULL, NULL, NULL, NULL, 'manual', NULL, NULL, NULL, false, false);
INSERT INTO oidc_client VALUES('_8957eda35234902ba8343c0cdacac040310f17dfca','_322d16999f9da8b5abc9e9c0c08e853f60f4dc4804','RP-Initiated Logout Client','Client for testing RP-Initiated Logout','example-userpass','["https:\/\/localhost.emobix.co.uk:8443\/test\/a\/simplesamlphp-module-oidc\/callback","https:\/\/www.certification.openid.net\/test\/a\/simplesamlphp-module-oidc\/callback"]','["openid","profile","email","address","phone"]',1,1,NULL,'["https:\/\/localhost.emobix.co.uk:8443\/test\/a\/simplesamlphp-module-oidc\/post_logout_redirect"]',NULL,NULL,NULL, NULL, NULL, NULL, NULL, 'manual', NULL, NULL, NULL, false, false);
INSERT INTO oidc_client VALUES('_9fe2f7589ece1b71f5ef75a91847d71bc5125ec2a6','_3c0beb20194179c01d7796c6836f62801e9ed4b368','Back-Channel Logout Client','Client for testing Back-Channel Logout','example-userpass','["https:\/\/localhost.emobix.co.uk:8443\/test\/a\/simplesamlphp-module-oidc\/callback","https:\/\/www.certification.openid.net\/test\/a\/simplesamlphp-module-oidc\/callback"]','["openid","profile","email","address","phone"]',1,1,NULL,'["https:\/\/localhost.emobix.co.uk:8443\/test\/a\/simplesamlphp-module-oidc\/post_logout_redirect"]','https://httpd:8443/test/a/simplesamlphp-module-oidc/backchannel_logout',NULL,NULL, NULL, NULL, NULL, NULL, 'manual', NULL, NULL, NULL, false, false);
CREATE TABLE oidc_access_token (
            id VARCHAR(191) PRIMARY KEY NOT NULL,
            scopes TEXT,
            expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            user_id VARCHAR(191) NOT NULL,
            client_id VARCHAR(191) NOT NULL,
            is_revoked BOOLEAN NOT NULL DEFAULT false,
            auth_code_id varchar(191) DEFAULT NULL, requested_claims TEXT NULL,
            flow_type CHAR(64) NULL,
            authorization_details TEXT NULL,
            bound_client_id TEXT NULL,
            bound_redirect_uri TEXT NULL,
            CONSTRAINT FK_43C1650EA76ED395 FOREIGN KEY (user_id)
                REFERENCES oidc_user (id) ON DELETE CASCADE,
            CONSTRAINT FK_43C1650E19EB6921 FOREIGN KEY (client_id)
                REFERENCES oidc_client (id) ON DELETE CASCADE
        );
CREATE TABLE oidc_refresh_token (
            id VARCHAR(191) PRIMARY KEY NOT NULL,
            expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            access_token_id VARCHAR(191) NOT NULL,
            is_revoked BOOLEAN NOT NULL DEFAULT false,
            auth_code_id varchar(191) DEFAULT NULL,
            CONSTRAINT FK_636B86402CCB2688 FOREIGN KEY (access_token_id)
                REFERENCES oidc_access_token (id) ON DELETE CASCADE
        );
CREATE TABLE oidc_auth_code (
            id VARCHAR(191) PRIMARY KEY NOT NULL,
            scopes TEXT,
            expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            user_id VARCHAR(191) NOT NULL,
            client_id VARCHAR(191) NOT NULL,
            is_revoked BOOLEAN NOT NULL DEFAULT false,
            redirect_uri TEXT NOT NULL, nonce TEXT NULL,
            flow_type CHAR(64) DEFAULT NULL,
            tx_code varchar(191) DEFAULT NULL,
            authorization_details TEXT NULL,
            bound_client_id TEXT NULL,
            bound_redirect_uri TEXT NULL,
            CONSTRAINT FK_97D32CA7A76ED395 FOREIGN KEY (user_id)
                REFERENCES oidc_user (id) ON DELETE CASCADE,
            CONSTRAINT FK_97D32CA719EB6921 FOREIGN KEY (client_id)
                REFERENCES oidc_client (id) ON DELETE CASCADE
        );
CREATE TABLE oidc_allowed_origin (
            client_id varchar(191) NOT NULL,
            origin varchar(191) NOT NULL,
            PRIMARY KEY (client_id, origin),
            CONSTRAINT FK_A027AF1E19EB6921 FOREIGN KEY (client_id)
                REFERENCES oidc_client (id) ON DELETE CASCADE
        );
CREATE TABLE oidc_session_logout_ticket (
           sid VARCHAR(191) NOT NULL,
           created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE oidc_vci_issuer_state (
    value CHAR(64) PRIMARY KEY NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_revoked BOOLEAN NOT NULL DEFAULT false
);
COMMIT;
