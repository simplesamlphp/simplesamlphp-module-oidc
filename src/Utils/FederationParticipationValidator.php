<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils;

use SimpleSAML\Module\oidc\Codebooks\LimitsEnum;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Exceptions\TrustMarkException;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\Federation\EntityStatement;
use SimpleSAML\OpenID\Federation\TrustChain;

class FederationParticipationValidator
{
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly Federation $federation,
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
        $leafEntityConfiguration = $trustChain->getResolvedLeaf();
        $trustAnchorEntityConfiguration = $trustChain->getResolvedTrustAnchor();

        $this->loggerService->debug(
            sprintf(
                'Validating federation participation by Trust Marks for leaf %s and Trust Anchor %s.',
                $leafEntityConfiguration->getIssuer(),
                $trustAnchorEntityConfiguration->getIssuer(),
            ),
        );

        $trustMarkLimitsRules = $this->moduleConfig->getTrustMarksNeededForFederationParticipationFor(
            $trustAnchorEntityConfiguration->getIssuer(),
        );

        if (empty($trustMarkLimitsRules)) {
            $this->loggerService->debug(
                'No Trust Mark limits imposed for ' . $trustAnchorEntityConfiguration->getIssuer(),
            );
            return;
        }

        $this->loggerService->debug(
            'Trust Mark limits for ' . $trustAnchorEntityConfiguration->getIssuer(),
            $trustMarkLimitsRules,
        );


        /**
         * @var string $limitId
         * @var non-empty-string[] $limitedTrustMarkIds
         */
        foreach ($trustMarkLimitsRules as $limitId => $limitedTrustMarkIds) {
            $limit = LimitsEnum::from($limitId);

            if ($limit === LimitsEnum::OneOf) {
                $this->validateForOneOfLimit(
                    $limitedTrustMarkIds,
                    $leafEntityConfiguration,
                    $trustAnchorEntityConfiguration,
                );
            } else {
                $this->validateForAllOfLimit(
                    $limitedTrustMarkIds,
                    $leafEntityConfiguration,
                    $trustAnchorEntityConfiguration,
                );
            }
        }
    }

    /**
     * @param non-empty-string[] $limitedTrustMarkIds
     * @throws \SimpleSAML\OpenID\Exceptions\EntityStatementException
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     * @throws \SimpleSAML\OpenID\Exceptions\TrustMarkException
     */
    public function validateForOneOfLimit(
        array $limitedTrustMarkIds,
        EntityStatement $leafEntityConfiguration,
        EntityStatement $trustAnchorEntityConfiguration,
    ): void {
        if (empty($limitedTrustMarkIds)) {
            $this->loggerService->debug('No Trust Mark limits given for OneOf limit rule, nothing to do.');
            return;
        }

        $this->loggerService->debug(
            sprintf(
                'Validating that entity %s has at least one valid Trust Mark for Trust Anchor %s.',
                $leafEntityConfiguration->getIssuer(),
                $trustAnchorEntityConfiguration->getIssuer(),
            ),
            ['limitedTrustMarkIds' => $limitedTrustMarkIds],
        );

        foreach ($limitedTrustMarkIds as $limitedTrustMarkId) {
            try {
                $this->federation->trustMarkValidator()->fromCacheOrDoForTrustMarkId(
                    $limitedTrustMarkId,
                    $leafEntityConfiguration,
                    $trustAnchorEntityConfiguration,
                );

                $this->loggerService->debug(
                    sprintf(
                        'Trust Mark ID %s validated using OneOf limit rule for entity %s under Trust Anchor %s.',
                        $limitedTrustMarkId,
                        $leafEntityConfiguration->getIssuer(),
                        $trustAnchorEntityConfiguration->getIssuer(),
                    ),
                );
                return;
            } catch (\Throwable $exception) {
                $this->loggerService->debug(
                    sprintf(
                        'Trust Mark ID %s validation failed with error: %s. Trying next if available.',
                        $limitedTrustMarkId,
                        $exception->getMessage(),
                    ),
                );
                continue;
            }
        }

        $error = sprintf(
            'Leaf entity %s does not have any valid Trust Marks from the given list (%s). OneOf limit rule failed.',
            $leafEntityConfiguration->getIssuer(),
            implode(',', $limitedTrustMarkIds),
        );

        $this->loggerService->error($error);
        throw new TrustMarkException($error);
    }

    /**
     * @param non-empty-string[] $limitedTrustMarkIds
     * @throws \SimpleSAML\OpenID\Exceptions\EntityStatementException
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     * @throws \SimpleSAML\OpenID\Exceptions\TrustMarkException
     */
    public function validateForAllOfLimit(
        array $limitedTrustMarkIds,
        EntityStatement $leafEntityConfiguration,
        EntityStatement $trustAnchorEntityConfiguration,
    ): void {
        if (empty($limitedTrustMarkIds)) {
            $this->loggerService->debug('No Trust Mark limits given for AllOf limit rule, nothing to do.');
            return;
        }

        $this->loggerService->debug(
            sprintf(
                'Validating that entity %s has all valid Trust Marks for Trust Anchor %s.',
                $leafEntityConfiguration->getIssuer(),
                $trustAnchorEntityConfiguration->getIssuer(),
            ),
            ['limitedTrustMarkIds' => $limitedTrustMarkIds],
        );

        foreach ($limitedTrustMarkIds as $limitedTrustMarkId) {
            try {
                $this->federation->trustMarkValidator()->fromCacheOrDoForTrustMarkId(
                    $limitedTrustMarkId,
                    $leafEntityConfiguration,
                    $trustAnchorEntityConfiguration,
                );

                $this->loggerService->debug(
                    sprintf(
                        'Trust Mark ID %s validated. Trying next if available.',
                        $limitedTrustMarkId,
                    ),
                );
            } catch (\Throwable $exception) {
                $error = sprintf(
                    'Trust Mark ID %s validation failed with error: %s. AllOf limit rule failed.',
                    $limitedTrustMarkId,
                    $exception->getMessage(),
                );
                $this->loggerService->error($error);
                throw new TrustMarkException($error);
            }
        }

        $this->loggerService->debug(
            sprintf(
                'Entity %s has all valid Trust Marks for Trust Anchor %s.',
                $leafEntityConfiguration->getIssuer(),
                $trustAnchorEntityConfiguration->getIssuer(),
            ),
        );
    }
}
