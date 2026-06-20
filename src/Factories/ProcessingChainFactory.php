<?php

declare(strict_types=1);

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Module\oidc\Factories;

use SimpleSAML\Auth\ProcessingChain;

class ProcessingChainFactory
{
    /**
     * @codeCoverageIgnore
     * @throws \Exception
     */
    public function build(array $state): ProcessingChain
    {
        // The IdP- and SP-side metadata (entityid + authproc filter lists) is
        // the single source of truth prepared in
        // AuthenticationService::runAuthProcs() and stored in the state.
        // Here we only consume it;
        // The IdP side carries the global authproc filters, the SP side the
        // per-client ones, and the SimpleSAMLphp ProcessingChain merges them
        // by priority.
        $idpMetadata = [
            'entityid' => $state['Source']['entityid'] ?? '',
            'authproc' => $state['Source']['authproc'] ?? [],
        ];
        $spMetadata = [
            'entityid' => $state['Destination']['entityid'] ?? '',
            'authproc' => $state['Destination']['authproc'] ?? [],
        ];

        return new ProcessingChain(
            $idpMetadata,
            $spMetadata,
            'oidc',
        );
    }
}
