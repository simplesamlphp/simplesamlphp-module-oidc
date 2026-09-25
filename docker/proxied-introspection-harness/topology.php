<?php

declare(strict_types=1);

/**
 * Who is who in the proxied introspection harness, and which credentials each party holds where (AARC-G052 proxied
 * token introspection across three OPs). Every node's module configuration and seed reads it, and so do the tests,
 * so the three can not drift apart.
 *
 * - a: the node which issued the token, asked by the hub.
 * - h: the hub, standing in for the EOSC AAI Federation hub. It knows the other nodes through its issuer map, and
 *   node b is a resource server to it.
 * - b: this OP as a node deploys it. Its next hop is the hub. The upstream mock stands in for the upstreams which
 *   misbehave, through its issuer map, which is what that option is for in a test setup.
 * - b-literal: b with AARC-G052 section 2.4's literal reading turned on, and the recording mock as its next hop, so
 *   that a test can see whether a token was sent upstream at all.
 * - b-loop: b with its own issuer as the next hop, a configuration error. The next hop's endpoint is the recording
 *   mock's, which b-loop may reach, so that the configuration check is the only thing which keeps the question from
 *   getting there.
 *
 * Test credentials only, for a stack which is reachable from nowhere but its own Docker network.
 */

$introspectionEndpoint = static fn(
    string $host,
    string $path = '/simplesaml/module.php/oidc/api/oauth2/token-introspection',
): string => 'https://' . $host . $path;

$mockHost = 'upstream-mock.oidc.test';
$mockUpstream = static fn(string $case, float $timeout = 2.0): array => [
    'issuer' => 'https://' . $mockHost . '/' . $case,
    'introspection_endpoint' => $introspectionEndpoint($mockHost, '/upstream-mock.php/' . $case),
    'client_id' => 'node-b',
    'client_secret' => 'node-b-secret-at-the-mock',
    'timeout' => $timeout,
];

// How each misbehaving upstream is reached from a node: by the issuer its tokens name, as the issuer map keys it.
$mockIssuerMap = [];
foreach (
    [
        'active' => 2.0,
        'inactive' => 2.0,
        'not-bearer' => 2.0,
        'server-error' => 2.0,
        'too-many-requests' => 2.0,
        'unauthorized' => 2.0,
        'not-json' => 2.0,
        // The mock answers after three seconds.
        'slow' => 1.0,
    ] as $case => $timeout
) {
    $upstream = $mockUpstream($case, $timeout);
    $mockIssuerMap[$upstream['issuer']] = $upstream;
}

// Every client is confidential, and authenticates with its secret.
$client = static fn(string $secret, array $extraMetadata = []): array => [
    'secret' => $secret,
    'scopes' => ['openid'],
    'extra_metadata' => $extraMetadata,
];

// A client which gets user tokens through the authorization code flow, to have something to introspect.
$relyingParty = static fn(string $secret): array => [
    'secret' => $secret,
    'scopes' => ['openid', 'profile', 'email'],
    'extra_metadata' => [],
];

return [
    'redirect_uri' => 'https://rp.oidc.test/callback',
    'user' => ['username' => 'student', 'password' => 'studentpass'],
    'upstream_mock_host' => $mockHost,
    'nodes' => [
        'a' => [
            'host' => 'a.oidc.test',
            'issuer' => 'https://a.oidc.test',
            'clients' => [
                'rp-a' => $relyingParty('rp-a-secret'),
                'hub-h' => $client('hub-h-secret-at-a'),
            ],
            'resource_server_client_ids' => [],
            'upstream_hub_client_ids' => ['hub-h'],
            'next_hop' => null,
            'issuer_map' => [],
            'upstream_failure_answers_inactive' => false,
            'outbound_allowed_hosts' => [],
        ],
        'h' => [
            'host' => 'h.oidc.test',
            'issuer' => 'https://h.oidc.test',
            'clients' => [
                'node-b' => $client('node-b-secret-at-h'),
                'rs-h' => $client('rs-h-secret'),
            ],
            'resource_server_client_ids' => ['node-b', 'rs-h'],
            'upstream_hub_client_ids' => [],
            'next_hop' => null,
            'issuer_map' => [
                'https://a.oidc.test' => [
                    'issuer' => 'https://a.oidc.test',
                    'introspection_endpoint' => $introspectionEndpoint('a.oidc.test'),
                    'client_id' => 'hub-h',
                    'client_secret' => 'hub-h-secret-at-a',
                ],
                'https://b.oidc.test' => [
                    'issuer' => 'https://b.oidc.test',
                    'introspection_endpoint' => $introspectionEndpoint('b.oidc.test'),
                    'client_id' => 'hub-h',
                    'client_secret' => 'hub-h-secret-at-b',
                    'client_authentication_method' => 'client_secret_post',
                ],
            ],
            'upstream_failure_answers_inactive' => false,
            'outbound_allowed_hosts' => ['a.oidc.test', 'b.oidc.test'],
        ],
        'b' => [
            'host' => 'b.oidc.test',
            'issuer' => 'https://b.oidc.test',
            'clients' => [
                'rp-b' => $relyingParty('rp-b-secret'),
                'hub-h' => $client('hub-h-secret-at-b'),
                // A resource server by its client record, the way an administrator makes one in the admin UI, and
                // allowed node a's tokens only.
                'rs-allowed' => $client('rs-allowed-secret', [
                    'introspection_resource_server' => true,
                    'introspection_foreign_issuers' => ['allow' => ['https://a.oidc.test']],
                ]),
                // A resource server by configuration, refused node a's tokens.
                'rs-denied' => $client('rs-denied-secret', [
                    'introspection_foreign_issuers' => ['deny' => ['https://a.oidc.test']],
                ]),
                // A resource server allowed every issuer.
                'rs-open' => $client('rs-open-secret'),
            ],
            'resource_server_client_ids' => ['rs-denied', 'rs-open'],
            'upstream_hub_client_ids' => ['hub-h'],
            'next_hop' => [
                'issuer' => 'https://h.oidc.test',
                'introspection_endpoint' => $introspectionEndpoint('h.oidc.test'),
                'client_id' => 'node-b',
                'client_secret' => 'node-b-secret-at-h',
            ],
            'issuer_map' => $mockIssuerMap,
            'upstream_failure_answers_inactive' => false,
            'outbound_allowed_hosts' => ['h.oidc.test', $mockHost],
        ],
        'b-literal' => [
            'host' => 'b-literal.oidc.test',
            'issuer' => 'https://b-literal.oidc.test',
            'clients' => [
                'rs-open' => $client('rs-open-secret'),
            ],
            'resource_server_client_ids' => ['rs-open'],
            'upstream_hub_client_ids' => [],
            'next_hop' => $mockUpstream('recorder'),
            'issuer_map' => $mockIssuerMap,
            'upstream_failure_answers_inactive' => true,
            'outbound_allowed_hosts' => [$mockHost],
        ],
        'b-loop' => [
            'host' => 'b-loop.oidc.test',
            'issuer' => 'https://b-loop.oidc.test',
            'clients' => [
                'rs-open' => $client('rs-open-secret'),
            ],
            'resource_server_client_ids' => ['rs-open'],
            'upstream_hub_client_ids' => [],
            'next_hop' => ['issuer' => 'https://b-loop.oidc.test'] + $mockUpstream('recorder'),
            'issuer_map' => [],
            'upstream_failure_answers_inactive' => false,
            'outbound_allowed_hosts' => [$mockHost],
        ],
    ],
];
