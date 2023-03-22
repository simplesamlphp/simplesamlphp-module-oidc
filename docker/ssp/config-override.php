<?php
$config['module.enable']['exampleauth'] = true;
$config['module.enable']['oidc'] = true;
$config = [
        'secretsalt' => 'testsalt',
        'database.dsn' => 'sqlite:/var/simplesamlphp/data/mydb.sq3',
        'database.username' => 'user',
        'database.password' => 'password',
        'language.i18n.backend' => 'gettext/gettext',
        'logging.level' => 7,
        'usenewui' => false,
    ] + $config;