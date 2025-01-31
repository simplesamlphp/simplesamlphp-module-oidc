<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils;

use SimpleSAML\Module\oidc\Codebooks\LimitsEnum;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Exceptions\TrustMarkException;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\Federation\Claims\TrustMarksClaimBag;
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
                $this->validateTrustMarksClaimBagAsOneOfLimit(
                    $limitedTrustMarkIds,
                    $leafEntityConfiguration,
                    $trustAnchorEntityConfiguration,
                );
            } else {
                $this->validateTrustMarksClaimBagAsAllOfLimit(
                    $limitedTrustMarkIds,
                    $leafEntityConfiguration,
                    $trustAnchorEntityConfiguration,
                );
            }
        }
    }

    /**
     * @throws \SimpleSAML\OpenID\Exceptions\EntityStatementException
     * @throws \SimpleSAML\OpenID\Exceptions\InvalidValueException
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     * @throws \SimpleSAML\OpenID\Exceptions\TrustMarkException
     */
    protected function ensureTrustMarksClaimBag(EntityStatement $leafEntityConfiguration): TrustMarksClaimBag
    {
        $leafTrustMarksClaimBag = $leafEntityConfiguration->getTrustMarks();

        if (is_null($leafTrustMarksClaimBag)) {
            $error = sprintf(
                'Leaf entity %s does not have any Trust Marks available.',
                $leafEntityConfiguration->getIssuer(),
            );

            $this->loggerService->error($error);
            throw new TrustMarkException($error);
        }

        $this->loggerService->debug(
            'Leaf has Trust Marks available.',
            ['leafTrustMarksClaimBag' => $leafTrustMarksClaimBag->jsonSerialize()],
        );

        return $leafTrustMarksClaimBag;
    }

    /**
     * @param non-empty-string[] $limitedTrustMarkIds
     * @throws \SimpleSAML\OpenID\Exceptions\EntityStatementException
     * @throws \SimpleSAML\OpenID\Exceptions\InvalidValueException
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     * @throws \SimpleSAML\OpenID\Exceptions\TrustMarkException
     */
    public function validateTrustMarksClaimBagAsOneOfLimit(
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

        $trustMarksClaimBag = $this->ensureTrustMarksClaimBag($leafEntityConfiguration);

        foreach ($limitedTrustMarkIds as $limitedTrustMarkId) {
            $trustMarksClaimValues = $trustMarksClaimBag->gerAllFor($limitedTrustMarkId);
            if (empty($trustMarksClaimValues)) {
                $this->loggerService->debug(
                    sprintf(
                        'There are no claims for Trust Mark ID %s. Trying next if available.',
                        $limitedTrustMarkId,
                    ),
                );
                continue;
            }

            $this->loggerService->debug(
                sprintf(
                    'There is/are %s claim/claims for Trust Mark ID %s.',
                    count($trustMarksClaimValues),
                    $limitedTrustMarkId,
                ),
            );

            foreach ($trustMarksClaimValues as $idx => $trustMarksClaimValue) {
                $this->loggerService->debug(
                    sprintf(
                        'Validating claim %s for Trust Mark ID %s',
                        $idx,
                        $limitedTrustMarkId,
                    ),
                    ['trustMarkClaim' => $trustMarksClaimValue->jsonSerialize()],
                );

                try {
                    $this->federation->trustMarkValidator()->forTrustMarksClaimValue(
                        $trustMarksClaimValue,
                        $leafEntityConfiguration,
                        $trustAnchorEntityConfiguration,
                    );

                    $this->loggerService->debug(
                        sprintf(
                            'Trust Mark ID %s validated using OneOf limit rule for entity %s for Trust Anchor %s.',
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
        }

        $error = sprintf(
            'Leaf entity %s does not have any valid Trust Marks from the given list (%s).',
            $leafEntityConfiguration->getIssuer(),
            implode(',', $limitedTrustMarkIds),
        );

        $this->loggerService->error($error);
        throw new TrustMarkException($error);
    }

    /**
     * @param non-empty-string[] $limitedTrustMarkIds
     * @throws \SimpleSAML\OpenID\Exceptions\InvalidValueException
     * @throws \SimpleSAML\OpenID\Exceptions\EntityStatementException
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     * @throws \SimpleSAML\OpenID\Exceptions\TrustMarkException
     */
    public function validateTrustMarksClaimBagAsAllOfLimit(
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

        $trustMarksClaimBag = $this->ensureTrustMarksClaimBag($leafEntityConfiguration);

        foreach ($limitedTrustMarkIds as $limitedTrustMarkId) {
            $trustMarksClaimValues = $trustMarksClaimBag->gerAllFor($limitedTrustMarkId);

            if (empty($trustMarksClaimValues)) {
                $error = sprintf(
                    'There are no claims for Trust Mark ID %s.',
                    $limitedTrustMarkId,
                );
                $this->loggerService->error($error);
                throw new TrustMarkException($error);
            }

            $this->loggerService->debug(
                sprintf(
                    'There is/are %s claim/claims for Trust Mark ID %s.',
                    count($trustMarksClaimValues),
                    $limitedTrustMarkId,
                ),
            );

            foreach ($trustMarksClaimValues as $idx => $trustMarksClaimValue) {
                $this->loggerService->debug(
                    sprintf(
                        'Validating claim %s for Trust Mark ID %s',
                        $idx,
                        $limitedTrustMarkId,
                    ),
                    ['trustMarkClaim' => $trustMarksClaimValue->jsonSerialize()],
                );

                try {
                    $this->federation->trustMarkValidator()->forTrustMarksClaimValue(
                        $trustMarksClaimValue,
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
                        'Trust Mark ID %s validation failed with error: %s.',
                        $limitedTrustMarkId,
                        $exception->getMessage(),
                    );
                    $this->loggerService->error($error);
                    throw new TrustMarkException($error);
                }
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
