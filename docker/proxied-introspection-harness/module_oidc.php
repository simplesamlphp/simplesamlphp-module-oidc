<?php

declare(strict_types=1);

use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;

/**
 * The module configuration of every OP node in the proxied introspection harness. HARNESS_NODE names the node, and
 * what differs between nodes is read from topology.php.
 */

$topology = require '/harness/topology.php';

$nodeName = getenv('HARNESS_NODE');
$node = $topology['nodes'][$nodeName] ?? null;

if (!is_array($node)) {
    throw new RuntimeException(sprintf('HARNESS_NODE names no node of the harness: %s', var_export($nodeName, true)));
}

$config = [
    ModuleConfig::OPTION_ISSUER => $node['issuer'],

    ModuleConfig::OPTION_TOKEN_AUTHORIZATION_CODE_TTL => 'PT10M',
    ModuleConfig::OPTION_TOKEN_REFRESH_TOKEN_TTL => 'P1D',
    ModuleConfig::OPTION_TOKEN_ACCESS_TOKEN_TTL => 'PT1H',

    // Each node has a key pair of its own, which run-on-start.sh puts in place.
    ModuleConfig::OPTION_PROTOCOL_SIGNATURE_KEY_PAIRS => [
        [
            ModuleConfig::KEY_ALGORITHM => SignatureAlgorithmEnum::RS256,
            ModuleConfig::KEY_PRIVATE_KEY_FILENAME => ModuleConfig::DEFAULT_PKI_PRIVATE_KEY_FILENAME,
            ModuleConfig::KEY_PUBLIC_KEY_FILENAME => ModuleConfig::DEFAULT_PKI_CERTIFICATE_FILENAME,
        ],
    ],

    ModuleConfig::OPTION_AUTH_SOURCE => 'example-userpass',
    ModuleConfig::OPTION_AUTH_USER_IDENTIFIER_ATTRIBUTE => 'uid',

    ModuleConfig::OPTION_API_ENABLED => true,
    ModuleConfig::OPTION_API_OAUTH2_TOKEN_INTROSPECTION_ENDPOINT_ENABLED => true,
    ModuleConfig::OPTION_API_OAUTH2_TOKEN_INTROSPECTION_RESOURCE_SERVER_CLIENT_IDS =>
        $node['resource_server_client_ids'],
    ModuleConfig::OPTION_API_OAUTH2_TOKEN_INTROSPECTION_UPSTREAM_HUB_CLIENT_IDS => $node['upstream_hub_client_ids'],
    ModuleConfig::OPTION_API_OAUTH2_TOKEN_INTROSPECTION_NEXT_HOP => $node['next_hop'],
    ModuleConfig::OPTION_API_OAUTH2_TOKEN_INTROSPECTION_ISSUER_MAP => $node['issuer_map'],
    ModuleConfig::OPTION_API_OAUTH2_TOKEN_INTROSPECTION_UPSTREAM_FAILURE_ANSWERS_INACTIVE =>
        $node['upstream_failure_answers_inactive'],

    // The other nodes are on a private Docker network, which the outbound destination policy refuses unless a
    // host is named here: the escape hatch a deployment with an internal hub would use.
    ModuleConfig::OPTION_OUTBOUND_ALLOWED_HOSTS => $node['outbound_allowed_hosts'],

    // TLS is verified, against the harness CA, which nothing else in the container trusts. The upstream
    // introspection client takes 'verify' over from these options.
    ModuleConfig::OPTION_PROTOCOL_HTTP_CLIENT_OPTIONS => [
        'verify' => '/harness/pki/ca.pem',
    ],
];
