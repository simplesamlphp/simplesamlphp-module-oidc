<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\StatusList;

use DateInterval;
use DateTimeImmutable;
use SimpleSAML\Module\oidc\Codebooks\StatusListKeyProfileEnum;
use SimpleSAML\Module\oidc\Exceptions\StatusListException;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\StatusListEntryRepository;
use SimpleSAML\Module\oidc\Repositories\StatusListRepository;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\StatusList\Contracts\StatusListTokenProviderInterface;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListPool;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListRecord;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListTokenResult;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Did;
use SimpleSAML\OpenID\TokenStatusList;
use SimpleSAML\OpenID\ValueAbstracts\KeyPair;
use Throwable;

/**
 * The Status List Token to serve for a list, signed on demand when the published one no longer holds.
 *
 * Re-signing happens here, on the read path, rather than on the path which revokes a credential. A
 * revocation is one small write which must not be made to wait on rebuilding and signing a list, and
 * several revocations arriving together would each sign a token only the last of which would be served.
 * The read path instead signs once per list per refresh interval however many changes accumulated.
 *
 * Everything used to build the token comes from the list's own row and not from configuration. A list
 * keeps the bits, capacity, validity, key and key profile it was created with, so changing a pool's
 * settings routes new credentials to new lists rather than altering what an existing list emits to
 * wallets already holding credentials which point at it.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\StatusList\DbStatusListTokenProviderTest
 */
class DbStatusListTokenProvider implements StatusListTokenProviderInterface
{
    /**
     * How many times a request will build a token before giving up and reporting failure.
     *
     * An attempt is spent only when this request genuinely lost to another one -- either a status
     * changed while it was signing, or another request published first -- and in the second case the
     * next attempt usually serves the winner's token rather than signing again. Three is generous for a
     * loop whose every iteration means a concurrent writer, and bounded so a pathologically busy list
     * fails visibly instead of tying up a worker.
     */
    protected const int MAX_PUBLISH_ATTEMPTS = 3;


    public function __construct(
        protected readonly StatusListRepository $statusListRepository,
        protected readonly StatusListEntryRepository $statusListEntryRepository,
        protected readonly StatusListContentHasher $statusListContentHasher,
        protected readonly StatusListKeyResolver $statusListKeyResolver,
        protected readonly TokenStatusList $tokenStatusList,
        protected readonly ModuleConfig $moduleConfig,
        protected readonly Did $did,
        protected readonly Helpers $helpers,
        protected readonly LoggerService $loggerService,
    ) {
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function getToken(string $statusListId): ?StatusListTokenResult
    {
        $statusList = $this->statusListRepository->findById($statusListId);

        // A list which is no longer served, and one which never existed, are the same answer to a
        // Relying Party. Being closed to new allocations is *not* one of those: a list stops accepting
        // credentials long before the ones already in it stop needing a status, so only retirement ends
        // publication.
        if (!$statusList instanceof StatusListRecord || $statusList->isRetired()) {
            return null;
        }

        $result = $this->publishedResult($statusList, $this->helpers->dateTime()->getUtc());

        // The overwhelmingly common case: the published token still describes the list and is not near
        // enough to its own expiry to want replacing, so nothing is read beyond the single row above.
        if ($result instanceof StatusListTokenResult) {
            return $result;
        }

        return $this->publish($statusList->getId());
    }


    /**
     * Builds, signs and publishes a token, or adopts one another request published in the meantime.
     *
     * @return ?\SimpleSAML\Module\oidc\StatusList\Values\StatusListTokenResult Null when the list turned out to be
     *   gone or retired.
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    protected function publish(string $statusListId): ?StatusListTokenResult
    {
        for ($attempt = 1; $attempt <= self::MAX_PUBLISH_ATTEMPTS; $attempt++) {
            // On the primary, unlike the read which got us here. What is about to be compared and set
            // has to be the current value, and a secondary's copy of it is not.
            $statusList = $this->statusListRepository->findByIdOnPrimary($statusListId);

            if (!$statusList instanceof StatusListRecord || $statusList->isRetired()) {
                return null;
            }

            $now = $this->helpers->dateTime()->getUtc();

            // Another request may have published between the read which decided to re-sign and this
            // one, in which case there is nothing left to do.
            $published = $this->publishedResult($statusList, $now);

            if ($published instanceof StatusListTokenResult) {
                return $published;
            }

            $observedContentHash = $statusList->getSignedTokenContentHash();
            // Read alongside the hash and compared alongside it below. The hash on its own cannot tell
            // a still-current snapshot from one a revocation superseded while it was being signed,
            // because both leave it empty.
            $observedInvalidationCounter = $statusList->getInvalidationCounter();
            $statuses = $this->statusListEntryRepository->findNonValidStatuses($statusListId);
            $contentHash = $this->statusListContentHasher->hash(
                $statusList->getBits(),
                $statusList->getCapacity(),
                $statuses,
            );

            $expiresAt = $now->add(
                new DateInterval('PT' . $statusList->getTokenValiditySeconds() . 'S'),
            );

            $token = $this->sign($statusList, $statuses, $now, $expiresAt);

            // Signing takes long enough for a revocation to land in the middle of it, and the
            // compare-and-set below would not notice: it compares the list row, which changing an
            // entry's status does not touch until the revoker's own invalidation lands. Re-reading the
            // entries and re-hashing is what catches that, at the cost of one indexed query.
            //
            // This narrows the window to the gap between this check and the update; it does not close
            // it, and closing it would need locking this design deliberately does without. That is
            // proportionate: a Relying Party is entitled to cache the result for `ttl`, which is hours,
            // so a token which is a few milliseconds behind is far inside the staleness the protocol
            // already sanctions.
            $currentContentHash = $this->statusListContentHasher->hash(
                $statusList->getBits(),
                $statusList->getCapacity(),
                $this->statusListEntryRepository->findNonValidStatuses($statusListId),
            );

            if ($currentContentHash !== $contentHash) {
                $this->loggerService->debug(
                    'Status List content changed while its token was being signed, so the token was ' .
                    'discarded and will be rebuilt.',
                    ['statusListId' => $statusListId, 'attempt' => $attempt],
                );

                continue;
            }

            if (
                $this->statusListRepository->publishToken(
                    $statusListId,
                    $observedContentHash,
                    $observedInvalidationCounter,
                    $contentHash,
                    $token,
                    $now,
                    $expiresAt,
                )
            ) {
                $this->loggerService->info('Published a Status List Token.', [
                    'statusListId' => $statusListId,
                    'expiresAt' => $expiresAt->getTimestamp(),
                ]);

                return new StatusListTokenResult(
                    $token,
                    $statusList->getTtlSeconds(),
                    $now,
                    $expiresAt,
                );
            }

            // Another request published first. The next pass re-reads and will normally find its token
            // and serve that, rather than signing again.
            $this->loggerService->debug(
                'Another request published a Status List Token first.',
                ['statusListId' => $statusListId, 'attempt' => $attempt],
            );
        }

        throw new StatusListException(
            sprintf(
                'Unable to publish a Status List Token for "%s" after %d attempts, because its content ' .
                'kept changing. Nothing was served, since a token which is out of date would report a ' .
                'revoked credential as valid.',
                $statusListId,
                self::MAX_PUBLISH_ATTEMPTS,
            ),
        );
    }


    /**
     * The published token, if there is one and it is still worth serving.
     *
     * Three ways it is not. It may have been invalidated by a status change, which is what an empty
     * content hash records. It may be old enough that the refresh interval has elapsed, which bounds how
     * long a change lost to a crash between the entry update and its invalidation can go unnoticed. Or
     * it may be close enough to its own expiry that a Relying Party caching it for the advertised `ttl`
     * would still be holding it after it expired.
     */
    protected function publishedResult(StatusListRecord $statusList, DateTimeImmutable $now): ?StatusListTokenResult
    {
        $token = $statusList->getSignedToken();
        $issuedAt = $statusList->getSignedTokenIssuedAt();
        $expiresAt = $statusList->getSignedTokenExpiresAt();

        if (
            !$statusList->hasPublishedToken() ||
            !is_string($token) ||
            !$issuedAt instanceof DateTimeImmutable ||
            !$expiresAt instanceof DateTimeImmutable
        ) {
            return null;
        }

        if ($now->getTimestamp() - $issuedAt->getTimestamp() > $statusList->getRefreshIntervalSeconds()) {
            return null;
        }

        if ($expiresAt->getTimestamp() - $now->getTimestamp() < $this->safetyMarginSeconds()) {
            return null;
        }

        return new StatusListTokenResult($token, $statusList->getTtlSeconds(), $issuedAt, $expiresAt);
    }


    /**
     * Builds the list from its entries and signs it.
     *
     * @param array<int,int> $statuses
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    protected function sign(
        StatusListRecord $statusList,
        array $statuses,
        DateTimeImmutable $issuedAt,
        DateTimeImmutable $expiresAt,
    ): string {
        // Deliberately the key this list was created with rather than the current one, and a failure to
        // find it is fatal here. Signing with today's key instead would produce a token which verifies
        // for nobody holding a credential bound to the old one, while looking like success.
        $signatureKeyPair = $this->statusListKeyResolver->getByKeyId($statusList->getSigningKeyId());
        $keyPair = $signatureKeyPair->getKeyPair();
        $identity = $this->identityFor($statusList->getKeyProfile(), $keyPair);

        try {
            $list = $this->tokenStatusList->statusListFactory()->fromEntries(
                $statuses,
                $statusList->getBits(),
                $statusList->getCapacity(),
            );

            return $this->tokenStatusList->statusListTokenFactory()->forStatusList(
                $list,
                // The stored URI, verbatim. A Relying Party checks that it matches the `uri` its
                // credential carries byte for byte, so rebuilding it from the current base URL would
                // break every credential issued before that URL last changed.
                $statusList->getUri(),
                $keyPair->getPrivateKey(),
                $signatureKeyPair->getSignatureAlgorithm(),
                $issuedAt,
                $expiresAt,
                new DateInterval('PT' . $statusList->getTtlSeconds() . 'S'),
                $identity['issuer'],
                [],
                [ClaimsEnum::Kid->value => $identity['keyId']],
            )->getToken();
        } catch (Throwable $throwable) {
            throw new StatusListException(
                sprintf(
                    'Unable to sign a Status List Token for "%s": %s',
                    $statusList->getId(),
                    $throwable->getMessage(),
                ),
                (int)$throwable->getCode(),
                $throwable,
            );
        }
    }


    /**
     * How the token says who signed it and with which key.
     *
     * The specification mandates no key resolution method, so this is the deployment's profile rather
     * than anything derivable from the spec, and it is read from the list's own row so that changing the
     * configured profile never alters a token wallets are already verifying.
     *
     * @return array{issuer: string, keyId: string}
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    protected function identityFor(StatusListKeyProfileEnum $keyProfile, KeyPair $keyPair): array
    {
        if ($keyProfile === StatusListKeyProfileEnum::Jwks) {
            return [
                'issuer' => $this->moduleConfig->getIssuer(),
                'keyId' => $keyPair->getKeyId(),
            ];
        }

        try {
            $didJwk = $this->did->didJwkResolver()->generateDidJwkFromJwk(
                $keyPair->getPublicKey()->jwk()->all(),
            );
        } catch (Throwable $throwable) {
            throw new StatusListException(
                'Unable to derive the did:jwk identifier for the Status List signing key: ' .
                $throwable->getMessage(),
                (int)$throwable->getCode(),
                $throwable,
            );
        }

        // The same shape the module already uses when signing Verifiable Credentials, so that a wallet
        // which can verify the credential can verify the Status List Token it points at.
        return [
            'issuer' => $didJwk,
            'keyId' => $didJwk . '#0',
        ];
    }


    /**
     * How close to expiry a published token is replaced rather than served.
     *
     * The same margin the pool validates its refresh interval against, so a token is always replaced
     * with time to spare rather than at the moment it becomes useless.
     */
    protected function safetyMarginSeconds(): int
    {
        return (new DateTimeImmutable('@0'))
            ->add(new DateInterval(StatusListPool::SAFETY_MARGIN))
            ->getTimestamp();
    }
}
