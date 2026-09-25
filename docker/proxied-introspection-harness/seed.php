<?php

declare(strict_types=1);

/**
 * Brings a harness node's database up to date and puts its clients in it, from topology.php, through the module's
 * own entity factory and repository, so that a stored client is what the module itself would store. Run by
 * run-on-start.sh, as the web server's user, every time the node starts.
 */

use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Factories\Entities\ClientEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;

require '/var/simplesamlphp/vendor/autoload.php';

$topology = require '/harness/topology.php';
$nodeName = (string)getenv('HARNESS_NODE');
$node = $topology['nodes'][$nodeName] ?? throw new RuntimeException('HARNESS_NODE names no node: ' . $nodeName);

(new DatabaseMigration())->migrate();

$moduleConfig = new ModuleConfig();
$clientEntityFactory = new ClientEntityFactory(new SspBridge(), new Helpers(), $moduleConfig);
$clientRepository = new ClientRepository($moduleConfig, Database::getInstance(), null, $clientEntityFactory);

foreach ($node['clients'] as $clientId => $client) {
    $clientEntity = $clientEntityFactory->fromData(
        id: $clientId,
        secret: $client['secret'],
        name: $clientId,
        description: sprintf('Proxied introspection harness client of node %s.', $nodeName),
        redirectUri: [$topology['redirect_uri']],
        scopes: $client['scopes'],
        isEnabled: true,
        isConfidential: true,
        extraMetadata: $client['extra_metadata'] === [] ? null : $client['extra_metadata'],
    );

    // Updated in place when it is there already, as on a restart, so that nothing which refers to it goes.
    is_null($clientRepository->findById($clientId)) ?
    $clientRepository->add($clientEntity) :
    $clientRepository->update($clientEntity);

    echo sprintf('Node %s: client %s in place.', $nodeName, $clientId), PHP_EOL;
}
