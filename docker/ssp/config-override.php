<?php

declare(strict_types=1);

$config['module.enable']['exampleauth'] = true;
$config['module.enable']['oidc'] = true;
// Have preprod warning enabled (though it may not be installed) to ease authproc redirect testing
$config['module.enable']['preprodwarning'] = true;
$config = [
        'secretsalt' => 'testsalt',
        'database.dsn' =>  getenv('DB.DSN') ?: 'sqlite:/var/simplesamlphp/data/mydb.sq3',
        'database.username' => getenv('DB.USERNAME') ?: 'user',
        'database.password' => getenv('DB.PASSWORD') ?: 'password',
        'logging.level' => 7,
        // SimpleSAMLphp logs to syslog by default under a web SAPI, and no syslog daemon runs in this
        // container, so module log messages would be written nowhere. Sending them to the PHP error log
        // puts them in Apache's, which the image serves on the container's stderr, so `docker compose
        // logs oidc-op` shows them - see the log dump the conformance workflow runs on failure. A refused
        // outbound destination is only visible there.
        'logging.handler' => 'errorlog',
        // Mail goes to the Mailpit container of docker/docker-compose.yml, which keeps it rather than
        // delivering it: the transaction code of a pre-authorized Credential Offer is read from there in the
        // OpenID4VCI conformance runs. SimpleSAMLphp refuses to send mail from the default technical contact.
        'technicalcontact_email' => 'oidc-conformance@example.org',
        'mail.transport.method' => 'smtp',
        'mail.transport.options' => [
            'host' => 'mailpit',
            'port' => 1025,
            'sender' => 'oidc-conformance@example.org',
        ],

    ] + $config;