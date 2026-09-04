<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\StatusList\Values;

use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\Codebooks\StatusListKeyProfileEnum;

/**
 * The configured Status List pools, indexed by their identifier.
 *
 * Building the bag is what establishes that a credential configuration resolves to exactly one pool.
 * Allocation needs a single answer to "which pool does this credential belong to", so a configuration
 * appearing in two pools is a configuration error rather than something to resolve by precedence.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\StatusList\StatusListPoolBagTest
 */
class StatusListPoolBag
{
    /** @var array<string,\SimpleSAML\Module\oidc\StatusList\Values\StatusListPool> */
    protected array $pools = [];

    /** @var array<string,string> Credential configuration ID to the ID of the pool it allocates from. */
    protected array $poolIdsByCredentialConfigurationId = [];


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function __construct(StatusListPool ...$pools)
    {
        foreach ($pools as $pool) {
            $this->add($pool);
        }
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    protected function add(StatusListPool $pool): void
    {
        if (array_key_exists($pool->getId(), $this->pools)) {
            throw new ConfigurationError(
                sprintf('Status List pool "%s" is defined more than once.', $pool->getId()),
            );
        }

        foreach ($pool->getCredentialConfigurationIds() as $credentialConfigurationId) {
            $existingPoolId = $this->poolIdsByCredentialConfigurationId[$credentialConfigurationId] ?? null;

            if ($existingPoolId !== null) {
                throw new ConfigurationError(
                    sprintf(
                        'Credential configuration "%s" is listed in both the "%s" and the "%s" Status ' .
                        'List pools, so there is no single policy its credentials would be allocated ' .
                        'under. List it in exactly one pool.',
                        $credentialConfigurationId,
                        $existingPoolId,
                        $pool->getId(),
                    ),
                );
            }

            $this->poolIdsByCredentialConfigurationId[$credentialConfigurationId] = $pool->getId();
        }

        $this->pools[$pool->getId()] = $pool;
    }


    /**
     * @return array<string,\SimpleSAML\Module\oidc\StatusList\Values\StatusListPool>
     */
    public function getAll(): array
    {
        return $this->pools;
    }


    public function getById(string $poolId): ?StatusListPool
    {
        return $this->pools[$poolId] ?? null;
    }


    public function isEmpty(): bool
    {
        return $this->pools === [];
    }


    /**
     * The pool a credential configuration allocates from, or null if it is not configured to use
     * Status Lists at all. Credentials of such a configuration are issued without a `status` claim.
     */
    public function getForCredentialConfigurationId(string $credentialConfigurationId): ?StatusListPool
    {
        $poolId = $this->poolIdsByCredentialConfigurationId[$credentialConfigurationId] ?? null;

        return $poolId === null ? null : $this->getById($poolId);
    }


    /**
     * @return string[]
     */
    public function getAllCredentialConfigurationIds(): array
    {
        return array_keys($this->poolIdsByCredentialConfigurationId);
    }


    /**
     * @param array<array-key,mixed> $config Pool identifier to that pool's settings.
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public static function fromConfig(
        array $config,
        StatusListKeyProfileEnum $defaultKeyProfile,
        ?string $issuerIdentifier = null,
    ): self {
        $pools = [];

        /** @var mixed $poolConfig */
        foreach ($config as $poolId => $poolConfig) {
            if (!is_string($poolId) || $poolId === '') {
                throw new ConfigurationError(
                    'Status List pools must be keyed by a non-empty pool identifier string.',
                );
            }

            if (!is_array($poolConfig)) {
                throw new ConfigurationError(
                    sprintf(
                        'Status List pool "%s" is configured with %s rather than an array of settings.',
                        $poolId,
                        get_debug_type($poolConfig),
                    ),
                );
            }

            $pools[] = StatusListPool::fromConfig(
                $poolId,
                $poolConfig,
                $defaultKeyProfile,
                $issuerIdentifier,
            );
        }

        return new self(...$pools);
    }
}
