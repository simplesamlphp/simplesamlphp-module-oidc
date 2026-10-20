<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\StatusList;

use DateInterval;
use DateTimeImmutable;
use SimpleSAML\Module\oidc\Codebooks\StatusListKeyProfileEnum;
use SimpleSAML\Module\oidc\Exceptions\StatusListException;
use SimpleSAML\Module\oidc\Factories\DidFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\StatusListEntryRepository;
use SimpleSAML\Module\oidc\Repositories\StatusListRepository;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\StatusList\Contracts\StatusListTokenProviderInterface;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListPool;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListRecord;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListTokenResult;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\VciCertificateChain;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Did\DidUrl;
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
        // The factory rather than the facade it builds. Building that one reads the DID cache adapter
        // and the outbound destination settings, none of which signing a token needs: both identifiers
        // below are minted from key material already in hand and nothing is fetched. Taking the facade
        // meant an unrelated outbound option could stop every Status List Token being signed, including
        // for lists whose profile resolves nothing at all.
        protected readonly DidFactory $didFactory,
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

            // Content which has not changed is published again only with a later `iat` than the published
            // token's (StatusListRepository::publishToken()), so within the second that token was issued in, or
            // while another node's clock runs ahead of this one, signing would only fail, three times over. The
            // token is served instead while it holds: it is current, and verifiable under the chain it carries,
            // which is all that a reason to replace it (a renewed certificate, the safety margin) needs of it
            // until the next second.
            $unreplaceable = $this->unreplaceableResult($statusList, $contentHash);

            if ($unreplaceable instanceof StatusListTokenResult) {
                return $unreplaceable;
            }

            $certificateChain = $this->certificateChainFor($statusList);
            $expiresAt = $this->expiryFor($statusList, $now, $certificateChain);

            $token = $this->sign($statusList, $statuses, $now, $expiresAt, $certificateChain);

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
     *
     * A list under the `x509` key profile adds a fourth: its token carries a chain other than the one its key
     * has now (a renewed certificate), which retires it, though it would still verify. And it changes the
     * third: a token which expires with its certificate chain (expiryFor()) is served to its expiry, since
     * one signed now could not last longer. Replacing it within the safety margin would sign one for every
     * request, and two requests in one second could not both publish one (StatusListRepository::publishToken()
     * makes a re-signing of unchanged content later than the last), so the second would fail. A Relying Party
     * does not rely on it past its `exp` whatever its `ttl` (draft-ietf-oauth-status-list section 13.7).
     *
     * A chain which can not be resolved now (removed, unreadable, expired, or its key gone) does not retire
     * the published token, nor does the safety margin then. That token was signed under a chain validated
     * when it was signed, it expires no later than that chain does, and it is still current, or it would not
     * have got this far, while a replacement could not be signed. Refusing it would take the status of every
     * credential in the list offline over a fault which the next signing reports anyway, and sooner than that
     * the Credential Issuer metadata and issuance, which check the active key's chain on every request.
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

        $secondsLeft = $expiresAt->getTimestamp() - $now->getTimestamp();

        // Before the chain is resolved, which an expired token does not need, and whose fault would otherwise be
        // reported as a token being served.
        if ($secondsLeft <= 0) {
            return null;
        }

        $chainExpiresAt = null;
        $isChainUnresolved = false;

        if ($statusList->getKeyProfile() === StatusListKeyProfileEnum::X509) {
            try {
                $certificateChain = $this->certificateChainFor($statusList);
                $chainExpiresAt = $certificateChain?->getEarliestNotAfter();
            } catch (Throwable $throwable) {
                $certificateChain = null;
                $isChainUnresolved = true;
                $this->loggerService->error(
                    'The certificate chain of a Status List\'s key can not be used, so its published token is ' .
                    'served until it is due to be replaced, when signing will fail: ' . $throwable->getMessage(),
                    ['statusListId' => $statusList->getId()],
                );
            }

            // Resolving the chain reads files and validates a path, which can take long enough for the token to have
            // expired since $now, and both ways past the safety margin below serve it to its expiry.
            $secondsLeft = $expiresAt->getTimestamp() - $this->helpers->dateTime()->getUtc()->getTimestamp();

            if ($secondsLeft <= 0) {
                return null;
            }

            if ($certificateChain !== null && $this->x5cOf($token) !== $certificateChain->getX5c()) {
                return null;
            }
        }

        if (
            $secondsLeft < $this->safetyMarginSeconds() &&
            !$isChainUnresolved &&
            ($chainExpiresAt === null || $expiresAt->getTimestamp() < $chainExpiresAt)
        ) {
            return null;
        }

        return new StatusListTokenResult($token, $statusList->getTtlSeconds(), $issuedAt, $expiresAt);
    }


    /**
     * The published token, when its content is that of the list now and it was issued no earlier than now
     * (publish()). Asked of the clock now, not of the moment the list was read: the status query in between can
     * take long enough for the token to have expired.
     */
    protected function unreplaceableResult(StatusListRecord $statusList, string $contentHash): ?StatusListTokenResult
    {
        $now = $this->helpers->dateTime()->getUtc();
        $token = $statusList->getSignedToken();
        $issuedAt = $statusList->getSignedTokenIssuedAt();
        $expiresAt = $statusList->getSignedTokenExpiresAt();

        if (
            !$statusList->hasPublishedToken() ||
            $statusList->getSignedTokenContentHash() !== $contentHash ||
            !is_string($token) ||
            !$issuedAt instanceof DateTimeImmutable ||
            !$expiresAt instanceof DateTimeImmutable ||
            $issuedAt->getTimestamp() < $now->getTimestamp() ||
            $expiresAt->getTimestamp() <= $now->getTimestamp()
        ) {
            return null;
        }

        return new StatusListTokenResult($token, $statusList->getTtlSeconds(), $issuedAt, $expiresAt);
    }


    /**
     * The `x5c` header parameter of a token this provider signed, or null for one which has none or can not be read.
     */
    protected function x5cOf(string $token): mixed
    {
        try {
            /** @var mixed $header */
            $header = json_decode(
                $this->tokenStatusList->helpers()->base64Url()->decode(explode('.', $token, 2)[0]),
                true,
                512,
                JSON_THROW_ON_ERROR,
            );
        } catch (Throwable) {
            return null;
        }

        return is_array($header) ? ($header[ClaimsEnum::X5c->value] ?? null) : null;
    }


    /**
     * The certificate chain the list's tokens carry: that of the key the list was created with, for a list under the
     * `x509` key profile, and none for another.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    protected function certificateChainFor(StatusListRecord $statusList): ?VciCertificateChain
    {
        if ($statusList->getKeyProfile() !== StatusListKeyProfileEnum::X509) {
            return null;
        }

        return $this->statusListKeyResolver->getCertificateChainFor(
            $this->statusListKeyResolver->getByKeyId($statusList->getSigningKeyId()),
        );
    }


    /**
     * When a token signed now expires: after the list's token validity, or when its certificate chain stops
     * validating, whichever comes first, so that no token outlives a certificate it carries. An intermediate, or the
     * trust anchor, may expire before the leaf. The cache lifetimes a token is served with stop at its expiry too
     * (StatusListTokenResult::getMaxAgeSeconds(), and its `ttl` claim in sign()).
     *
     * Such a token is served to its expiry rather than replaced within the safety margin (publishedResult()), and
     * signing fails once the chain has expired. The warning logged whenever a token is cut short is what tells the
     * operator to renew in time.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    protected function expiryFor(
        StatusListRecord $statusList,
        DateTimeImmutable $now,
        ?VciCertificateChain $certificateChain,
    ): DateTimeImmutable {
        $expiresAt = $now->add(new DateInterval('PT' . $statusList->getTokenValiditySeconds() . 'S'));

        if (!$certificateChain instanceof VciCertificateChain) {
            return $expiresAt;
        }

        try {
            $chainExpiresAt = $certificateChain->getEarliestNotAfter();
        } catch (Throwable $throwable) {
            throw new StatusListException(
                'Unable to read when the certificate chain of a Status List\'s key expires: ' .
                $throwable->getMessage(),
                (int)$throwable->getCode(),
                $throwable,
            );
        }

        if ($chainExpiresAt >= $expiresAt->getTimestamp()) {
            return $expiresAt;
        }

        // The chain was valid when it was resolved, earlier in this request, but the status query since may have
        // taken long enough for it not to be any more. Asked of the clock now rather than of the moment the token
        // is issued at: a token signed now would be expired already.
        if ($chainExpiresAt <= $this->helpers->dateTime()->getUtc()->getTimestamp()) {
            throw new StatusListException(
                sprintf(
                    'The certificate chain of the key of Status List "%s" has expired, so the list can not be signed.',
                    $statusList->getId(),
                ),
            );
        }

        $this->loggerService->warning(
            'A Status List Token expires early because a certificate of its key\'s chain does. Renew the ' .
            'certificate, or the list can not be signed once it has expired.',
            ['statusListId' => $statusList->getId(), 'chainExpiresAt' => $chainExpiresAt],
        );

        return (new DateTimeImmutable('@' . $chainExpiresAt))->setTimezone($now->getTimezone());
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
        ?VciCertificateChain $certificateChain,
    ): string {
        // Deliberately the key this list was created with rather than the current one, and a failure to
        // find it is fatal here. Signing with today's key instead would produce a token which verifies
        // for nobody holding a credential bound to the old one, while looking like success.
        $signatureKeyPair = $this->statusListKeyResolver->getByKeyId($statusList->getSigningKeyId());
        $keyPair = $signatureKeyPair->getKeyPair();
        $identity = $this->identityFor($statusList, $keyPair, $certificateChain);

        // A Relying Party may keep the token for its `ttl`, so that stops at the token's expiry too, which a
        // certificate chain may have brought forward (expiryFor()).
        $ttlSeconds = min(
            $statusList->getTtlSeconds(),
            max(1, $expiresAt->getTimestamp() - $issuedAt->getTimestamp()),
        );

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
                new DateInterval('PT' . $ttlSeconds . 'S'),
                $identity['issuer'],
                [],
                $identity['header'],
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
     * than anything derivable from the spec. The whole record is taken rather than the profile alone
     * because the answer is assembled from the row and not from configuration -- both the profile and,
     * under `did_web`, the identifier itself -- so that changing a setting never alters a token wallets
     * are already verifying. Under `x509` the key's certificate chain, which is configuration, is what names
     * the key (StatusListKeyProfileEnum::X509).
     *
     * @return array{issuer: string, header: array<non-empty-string,mixed>}
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    protected function identityFor(
        StatusListRecord $statusList,
        KeyPair $keyPair,
        ?VciCertificateChain $certificateChain,
    ): array {
        return match ($statusList->getKeyProfile()) {
            StatusListKeyProfileEnum::Jwks => [
                'issuer' => $this->moduleConfig->getIssuer(),
                'header' => [ClaimsEnum::Kid->value => $keyPair->getKeyId()],
            ],
            StatusListKeyProfileEnum::DidWeb => $this->didWebIdentityFor($statusList, $keyPair),
            StatusListKeyProfileEnum::DidJwk => $this->didJwkIdentityFor($keyPair),
            StatusListKeyProfileEnum::X509 => [
                'issuer' => $this->moduleConfig->getIssuer(),
                'header' => [
                    ClaimsEnum::X5c->value => $certificateChain?->getX5c() ?? throw new StatusListException(
                        sprintf(
                            'Status List "%s" is under the "%s" key profile, but no certificate chain was given to ' .
                            'sign it with.',
                            $statusList->getId(),
                            StatusListKeyProfileEnum::X509->value,
                        ),
                    ),
                ],
            ],
        };
    }


    /**
     * @return array{issuer: string, header: array<non-empty-string,mixed>}
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    protected function didJwkIdentityFor(KeyPair $keyPair): array
    {
        try {
            $didJwk = $this->didFactory->didJwkResolver()->generateDidJwkFromJwk(
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
            'header' => [ClaimsEnum::Kid->value => $didJwk . '#0'],
        ];
    }


    /**
     * The identifier comes from the list's own row and is never re-derived from configuration, so a
     * list keeps naming the issuer it was created under even after that setting changes or is cleared.
     * The key is named through the same factory which builds the published DID document, so a token can
     * not point at a verification method that document does not carry.
     *
     * @return array{issuer: string, header: array<non-empty-string,mixed>}
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    protected function didWebIdentityFor(StatusListRecord $statusList, KeyPair $keyPair): array
    {
        $didWeb = $statusList->getIssuerIdentifier();

        if (is_null($didWeb)) {
            // Only reachable for a row written by something other than the allocator, which refuses
            // this profile without an identifier long before a list exists. Signing under a guessed
            // identity would be worse than not signing: the token would name an issuer this list was
            // never created under, and a wallet cannot tell the difference.
            throw new StatusListException(
                sprintf(
                    'Status List "%s" is recorded under the "%s" key profile but carries no issuer ' .
                    'identifier, so there is no issuer to sign it as.',
                    $statusList->getId(),
                    StatusListKeyProfileEnum::DidWeb->value,
                ),
            );
        }

        try {
            $keyId = $this->didFactory->didDocumentFactory()->verificationMethodIdFor(
                new DidUrl($didWeb),
                $keyPair->getKeyId(),
            )->getValue();
        } catch (Throwable $throwable) {
            throw new StatusListException(
                'Unable to build the did:web verification method identifier for the Status List ' .
                'signing key: ' . $throwable->getMessage(),
                (int)$throwable->getCode(),
                $throwable,
            );
        }

        return [
            'issuer' => $didWeb,
            'header' => [ClaimsEnum::Kid->value => $keyId],
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
