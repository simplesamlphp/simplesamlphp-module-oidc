<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils;

use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Federation\TrustChain;

class FederationParticipationValidator
{
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly LoggerService $loggerService,
    ) {
    }

    public function byTrustMarksFor(TrustChain $trustChain): void
    {
        $trustAnchor = $trustChain->getResolvedTrustAnchor();

        $trustMarkLimitsRules = $this->moduleConfig
            ->getTrustMarksNeededForFederationParticipationFor($trustAnchor->getIssuer());

        if (empty($trustMarkLimitsRules)) {
            $this->loggerService->debug('No Trust Mark limits emposed for ' . $trustAnchor->getIssuer());
            return;
        }

        $this->loggerService->debug('Trust Mark limits for ' . $trustAnchor->getIssuer(), $trustMarkLimitsRules);

        //$leaf = $trustChain->getResolvedLeaf();
        //$leafTrustMarks = $leaf->getTrustMarks();

        // TODO mivanci continue
    }
}
