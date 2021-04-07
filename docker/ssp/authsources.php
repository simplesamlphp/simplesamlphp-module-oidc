<?php

$config = array(

    // This is a authentication source which handles admin authentication.
    'admin' => array(
        'core:AdminPassword',
    ),

    'example-userpass' => [
        'exampleauth:UserPass',
        'student:studentpass' => [
            'uid' => ['student'],
            'eduPersonAffiliation' => ['member', 'student'],
        ],
        'employee:employeepass' => [
            'uid' => ['employee'],
            'eduPersonAffiliation' => ['member', 'employee'],
        ],
    ],


);
