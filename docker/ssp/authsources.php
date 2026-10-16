<?php

declare(strict_types=1);

$config = array(

    // This is an authentication source which handles admin authentication.
    'admin' => array(
        'core:AdminPassword',
    ),

    // exampleauth:UserPass, where logging in as `cancel` (any password) cancels the authentication, which the
    // OIDC module answers to the client with access_denied; see docker/ssp/modules/oidcconformance.
    'example-userpass' => [
        'oidcconformance:CancellableUserPass',
        'users' => [
            'student:studentpass' => [
                'uid' => ['student'],
                'eduPersonAffiliation' => ['member', 'student'],
                'eduPersonNickname' => 'Sir_Nickname',
                'displayName' => 'Some User',
                'givenName' => 'Firsty',
                'middle_name' => 'Mid',
                'sn' => 'Lasty',
                'labeledURI' => 'https://example.com/student',
                'jpegURL' => 'https://example.com/student.jpg',
                'mail' => 'something@example.com',
                'email_verified' => 'yes',
                'zoneinfo' => 'Europe/Paris',
                'updated_at' => '1621374126',
                'preferredLanguage' => 'fr-CA',
                'website' => 'https://example.com/student-blog',
                'gender' => 'female',
                'birthdate' => '1945-03-21',
                'eduPersonUniqueId' => '13579',
                'phone_number_verified' => 'yes',
                'mobile' => '+1 (604) 555-1234;ext=5678',
                'postalAddress' => ["Place Charles de Gaulle, Paris"],
                'street_address' => ['Place Charles de Gaulle'],
                'locality' => ['Paris'],
                'region' => ['Île-de-France'],
                'postal_code' => ['75008'],
                'country' => ['France'],
            ],
            'employee:employeepass' => [
                'uid' => ['employee'],
                'eduPersonAffiliation' => ['member', 'employee'],
                'eduPersonEntitlement' => ['urn:example:oidc:manage:client']
            ],
            'member:memberpass' => [
                'uid' => ['member'],
                'eduPersonAffiliation' => ['member'],
                'eduPersonEntitlement' => ['urn:example:oidc:manage:client']
            ],
            'minimal:minimalpass' => [
                'uid' => ['minimal'],
            ],
        ],
    ],


);
