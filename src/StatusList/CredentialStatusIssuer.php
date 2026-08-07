<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\StatusList;

use DateTimeImmutable;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\StatusList\Contracts\StatusIndexAllocatorInterface;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListPool;
use SimpleSAML\OpenID\TokenStatusList;
use SimpleSAML\OpenID\TokenStatusList\StatusClaim;

/**
 * Gives a credential about to be issued the `status` claim which makes it revocable.
 *
 * This is the whole of what issuance needs to know about Status Lists: hand it a credential
 * configuration and the identifier the credential will carry, and get back either a claim to merge into
 * the payload or null, meaning this configuration was never set up to be revocable.
 *
 * Null and a failure are kept firmly apart. A configuration which belongs to no pool is a deliberate
 * choice, and its credentials are issued unchanged. A configuration which does belong to one but whose
 * index could not be claimed is a failure, and it is raised rather than swallowed: quietly issuing that
 * credential without a status claim would produce something no Relying Party can ever be told to stop
 * accepting, and neither the holder nor the issuer would have any sign that it happened.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\StatusList\CredentialStatusIssuerTest
 */
class CredentialStatusIssuer
{
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly StatusIndexAllocatorInterface $statusIndexAllocator,
        protected readonly SubjectRefHasher $subjectRefHasher,
        protected readonly TokenStatusList $tokenStatusList,
        protected readonly LoggerService $loggerService,
    ) {
    }

    /**
     * @param string $credentialConfigurationId Which configuration is being issued, deciding both
     * whether there is a pool at all and which one.
     * @param string $credentialId The `jti` the credential will carry, which has to be minted before
     * this is called, since claiming the index and recording what it was claimed for are one operation.
     * @param string $userIdentifier Hashed here and never stored as given.
     * @param ?DateTimeImmutable $expiresAt When the credential expires, or null if it never does.
     * @return ?StatusClaim Null when this configuration does not allocate Status List entries.
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\OpenID\Exceptions\InvalidValueException
     * @throws \JsonException
     * @throws \Exception
     */
    public function issueFor(
        string $credentialConfigurationId,
        string $credentialId,
        string $userIdentifier,
        ?DateTimeImmutable $expiresAt = null,
    ): ?StatusClaim {
        $pool = $this->moduleConfig->getVciStatusListPoolFor($credentialConfigurationId);

        if (!$pool instanceof StatusListPool) {
            return null;
        }

        // The index is claimed before the credential is signed, because the claim has to be in the
        // payload which gets signed. Should signing then fail, the index stays claimed by a credential
        // which was never handed out: one slot in a list of many thousands, sitting at the Valid status
        // it was seeded with, which is harmless and not worth the machinery it would take to reclaim.
        $allocation = $this->statusIndexAllocator->allocateFor(
            $pool,
            $credentialId,
            $credentialConfigurationId,
            $this->subjectRefHasher->hash($userIdentifier),
            $expiresAt,
        );

        $this->loggerService->debug(
            'Issuing a credential with a Status List reference.',
            [
                'credentialConfigurationId' => $credentialConfigurationId,
                'poolId' => $pool->getId(),
                'statusListId' => $allocation->getStatusListId(),
                'idx' => $allocation->getIdx(),
            ],
        );

        return $this->tokenStatusList->statusReferenceFactory()->buildClaim(
            $allocation->getUri(),
            $allocation->getIdx(),
        );
    }
}
