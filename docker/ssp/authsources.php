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
            'displayName' => 'Some User',
            'givenName' => 'Firsty',
            'sn' => 'Lasty',
            'mail' => 'something@example.com',
            'eduPersonUniqueId' => '13579'
        ],
        'employee:employeepass' => [
            'uid' => ['employee'],
            'eduPersonAffiliation' => ['member', 'employee'],
        ],
        'minimal:minimalpass' => [
            'uid' => ['minimal'],
        ],
    ],


);
