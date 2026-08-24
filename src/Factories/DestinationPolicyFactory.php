<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories;

use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Network\DestinationPolicy;

/**
 * Builds the single outbound destination policy this OP applies to everything it fetches.
 *
 * One instance is shared by every tool class that fetches (federation statements, `jwks_uri`,
 * `signed_jwks_uri`, `request_uri`, Status List Tokens) and by the Back-Channel Logout client, so that
 * "where this deployment may send a request" is answered in one place rather than per endpoint. The
 * policy is also usable without a request in hand, which is what lets a client registration refuse an
 * inward-pointing URI instead of discovering it at first fetch.
 */
class DestinationPolicyFactory
{
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly LoggerService $loggerService,
    ) {
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\OpenID\Exceptions\DestinationPolicyException On unusable configuration, which the
     *         library refuses when the policy is built rather than letting a range that can never match pass
     *         for a working exemption.
     * @throws \Exception
     */
    public function build(): DestinationPolicy
    {
        return new DestinationPolicy(
            allowedSchemes: $this->moduleConfig->getOutboundAllowedSchemes(),
            allowedHosts: $this->moduleConfig->getOutboundAllowedHosts(),
            allowedCidrs: $this->moduleConfig->getOutboundAllowedCidrs(),
            addressPinningMode: $this->moduleConfig->getOutboundAddressPinningMode(),
            logger: $this->loggerService,
        );
    }
}
