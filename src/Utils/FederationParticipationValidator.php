<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils;

use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Exceptions\TrustMarkException;
use SimpleSAML\OpenID\Federation\TrustChain;

class FederationParticipationValidator
{
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly LoggerService $loggerService,
    ) {
    }

    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\OpenID\Exceptions\EntityStatementException
     * @throws \SimpleSAML\OpenID\Exceptions\TrustChainException
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     * @throws \SimpleSAML\OpenID\Exceptions\TrustMarkException
     */
    public function byTrustMarksFor(TrustChain $trustChain): void
    {
        $trustAnchor = $trustChain->getResolvedTrustAnchor();

        $trustMarkLimitsRules = $this->moduleConfig->getTrustMarksNeededForFederationParticipationFor(
            $trustAnchor->getIssuer(),
        );

        if (empty($trustMarkLimitsRules)) {
            $this->loggerService->debug('No Trust Mark limits imposed for ' . $trustAnchor->getIssuer());
            return;
        }

        $this->loggerService->debug('Trust Mark limits for ' . $trustAnchor->getIssuer(), $trustMarkLimitsRules);

        $leaf = $trustChain->getResolvedLeaf();
        $leafTrustMarks = $leaf->getTrustMarks();

        if (is_null($leafTrustMarks)) {
            $error = sprintf(
                'Leaf entity %s does not have any Trust Marks available.',
                $leaf->getIssuer(),
            );

            $this->loggerService->error($error, compact('trustMarkLimitsRules'));
            throw new TrustMarkException($error);
        }

        // Leaf has some Trust Marks.

        // TODO mivanci continue
    }
}
