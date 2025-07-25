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
         * @var non-empty-string[] $limitedTrustMarkTypes
         */
        foreach ($trustMarkLimitsRules as $limitId => $limitedTrustMarkTypes) {
            $limit = LimitsEnum::from($limitId);

            if ($limit === LimitsEnum::OneOf) {
                $this->validateForOneOfLimit(
                    $limitedTrustMarkTypes,
                    $leafEntityConfiguration,
                    $trustAnchorEntityConfiguration,
                );
            } else {
                $this->validateForAllOfLimit(
                    $limitedTrustMarkTypes,
                    $leafEntityConfiguration,
                    $trustAnchorEntityConfiguration,
                );
            }
        }
    }

    /**
     * @param non-empty-string[] $limitedTrustMarkTypes
     * @throws \SimpleSAML\OpenID\Exceptions\EntityStatementException
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     * @throws \SimpleSAML\OpenID\Exceptions\TrustMarkException
     */
    public function validateForOneOfLimit(
        array $limitedTrustMarkTypes,
        EntityStatement $leafEntityConfiguration,
        EntityStatement $trustAnchorEntityConfiguration,
    ): void {
        if (empty($limitedTrustMarkTypes)) {
            $this->loggerService->debug('No Trust Mark limits given for OneOf limit rule, nothing to do.');
            return;
        }

        $this->loggerService->debug(
            sprintf(
                'Validating that entity %s has at least one valid Trust Mark for Trust Anchor %s.',
                $leafEntityConfiguration->getIssuer(),
                $trustAnchorEntityConfiguration->getIssuer(),
            ),
            ['limitedTrustMarkTypes' => $limitedTrustMarkTypes],
        );

        foreach ($limitedTrustMarkTypes as $limitedTrustMarkType) {
            try {
                $this->federation->trustMarkValidator()->fromCacheOrDoForTrustMarkType(
                    $limitedTrustMarkType,
                    $leafEntityConfiguration,
                    $trustAnchorEntityConfiguration,
                );

                $this->loggerService->debug(
                    sprintf(
                        'Trust Mark Type %s validated using OneOf limit rule for entity %s under Trust Anchor %s.',
                        $limitedTrustMarkType,
                        $leafEntityConfiguration->getIssuer(),
                        $trustAnchorEntityConfiguration->getIssuer(),
                    ),
                );
                return;
            } catch (\Throwable $exception) {
                $this->loggerService->debug(
                    sprintf(
                        'Trust Mark Type %s validation failed with error: %s. Trying next if available.',
                        $limitedTrustMarkType,
                        $exception->getMessage(),
                    ),
                );
                continue;
            }
        }

        $error = sprintf(
            'Leaf entity %s does not have any valid Trust Marks from the given list (%s). OneOf limit rule failed.',
            $leafEntityConfiguration->getIssuer(),
            implode(',', $limitedTrustMarkTypes),
        );

        $this->loggerService->error($error);
        throw new TrustMarkException($error);
    }

    /**
     * @param non-empty-string[] $limitedTrustMarkTypes
     * @throws \SimpleSAML\OpenID\Exceptions\EntityStatementException
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     * @throws \SimpleSAML\OpenID\Exceptions\TrustMarkException
     */
    public function validateForAllOfLimit(
        array $limitedTrustMarkTypes,
        EntityStatement $leafEntityConfiguration,
        EntityStatement $trustAnchorEntityConfiguration,
    ): void {
        if (empty($limitedTrustMarkTypes)) {
            $this->loggerService->debug('No Trust Mark limits given for AllOf limit rule, nothing to do.');
            return;
        }

        $this->loggerService->debug(
            sprintf(
                'Validating that entity %s has all valid Trust Marks for Trust Anchor %s.',
                $leafEntityConfiguration->getIssuer(),
                $trustAnchorEntityConfiguration->getIssuer(),
            ),
            ['limitedTrustMarkTypes' => $limitedTrustMarkTypes],
        );

        foreach ($limitedTrustMarkTypes as $limitedTrustMarkType) {
            try {
                $this->federation->trustMarkValidator()->fromCacheOrDoForTrustMarkType(
                    $limitedTrustMarkType,
                    $leafEntityConfiguration,
                    $trustAnchorEntityConfiguration,
                );

                $this->loggerService->debug(
                    sprintf(
                        'Trust Mark Type %s validated. Trying next if available.',
                        $limitedTrustMarkType,
                    ),
                );
            } catch (\Throwable $exception) {
                $error = sprintf(
                    'Trust Mark Type %s validation failed with error: %s. AllOf limit rule failed.',
                    $limitedTrustMarkType,
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
