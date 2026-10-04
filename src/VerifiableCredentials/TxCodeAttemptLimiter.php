<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\VerifiableCredentials;

use DateTimeInterface;
use RuntimeException;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;

/**
 * How many attempts a wallet gets at the Transaction Code of one pre-authorized code.
 *
 * A generated Transaction Code is four digits, 9,000 values, and the code it protects lives for the
 * authorization code lifetime (ten minutes by default), so without a limit it can be guessed: the
 * Transaction Code is what OpenID4VCI 1.0 (section 13.6.1) relies on against whoever read the Credential
 * Offer over the user's shoulder. Each attempt is taken from the pre-authorized code's budget, whatever
 * address it comes from, and once the budget is spent the code is refused for the rest of its life.
 *
 * The budget is kept in the protocol cache: written when the code is created (open()), and spent one attempt
 * at a time (admitAttempt()). Without a protocol cache nothing is kept and every attempt is admitted, which the
 * configuration template and the documentation say; a cache which keeps nothing from one request to the next
 * (ModuleConfig::isProtocolCacheKeptAcrossRequests()) counts as none, since a budget written while the offer is
 * made would be gone by the token request and every code refused.
 *
 * Counting down from a budget rather than up from nothing is what makes a cache which loses the count lock the
 * code rather than reopen it: Symfony's adapters answer a failed read with a miss, an evicted entry is a miss
 * too, and a miss counted up from nothing would be a fresh set of attempts. Here a missing budget refuses the
 * attempt, and the user needs a new offer.
 *
 * The budget is read and then written, as two operations, so attempts sent at the same moment can each see
 * the same budget and all be admitted; the limit holds for attempts made one after another. A write which does
 * not stick is refused with an exception, as is a cache which throws, and the endpoint answers server_error.
 * Symfony's adapters log a failed write rather than throw, so two things are checked: that the cache reports
 * the write as stored (the protocol cache's set() answers it; a chain of adapters reports a write one of its
 * layers lost, which a read answered from another layer would not show), and that the budget then reads back as
 * written (an adapter which stores nothing may still report the write as done).
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\VerifiableCredentials\TxCodeAttemptLimiterTest
 */
class TxCodeAttemptLimiter
{
    protected const string CACHE_KEY = 'vci-tx-code-attempts-left';

    /**
     * Kept past the code's own expiry, so that the budget does not go a moment before the code does on a
     * clock which runs behind.
     */
    protected const int TTL_MARGIN_SECONDS = 60;


    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly ?ProtocolCache $protocolCache,
        protected readonly Helpers $helpers,
        protected readonly LoggerService $loggerService,
    ) {
    }


    /**
     * Gives a newly created code which carries a Transaction Code its budget of attempts, the configured limit.
     *
     * @param string $preAuthorizedCodeId The code, as stored.
     * @param \DateTimeInterface $expiresAt When that code expires, which the budget is kept until.
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \RuntimeException When the cache does not keep the budget.
     */
    public function open(string $preAuthorizedCodeId, DateTimeInterface $expiresAt): void
    {
        if (!$this->isInForce()) {
            if ($this->protocolCache instanceof ProtocolCache) {
                $this->loggerService->warning(
                    'Transaction code attempts are not counted: the protocol cache adapter keeps nothing from one ' .
                    'request to the next.',
                );
            }

            return;
        }

        $limit = $this->moduleConfig->getVciTxCodeMaxAttempts();

        if (
            !$this->write($preAuthorizedCodeId, $limit, $expiresAt) ||
            $this->read($preAuthorizedCodeId) !== $limit
        ) {
            throw new RuntimeException(
                'Unable to give the pre-authorized code its transaction code attempts: the protocol cache did ' .
                'not keep them.',
            );
        }
    }


    /**
     * Takes one attempt at the Transaction Code of the code given, if one is left. Called before the
     * Transaction Code is compared, so that the attempt is spent whether it turns out right or wrong.
     *
     * @param string $preAuthorizedCodeId The code the attempt is made at, as stored.
     * @param \DateTimeInterface $expiresAt When that code expires, which the budget is kept until.
     * @return bool Whether the attempt may go ahead.
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \RuntimeException When the cache does not keep the spent attempt.
     */
    public function admitAttempt(string $preAuthorizedCodeId, DateTimeInterface $expiresAt): bool
    {
        if (!$this->isInForce()) {
            $this->loggerService->debug(
                'Transaction code attempts are not counted, since no protocol cache which keeps entries across ' .
                'requests is configured.',
            );

            return true;
        }

        $left = $this->read($preAuthorizedCodeId);

        if ($left === null) {
            // Never opened, evicted, or unreadable: none of them may count as a fresh set of attempts.
            $this->loggerService->warning(
                'No transaction code attempts are on record for the pre-authorized code, so none is admitted: ' .
                'its record was lost from the protocol cache, could not be read, or was never made.',
            );

            return false;
        }

        if ($left < 1) {
            return false;
        }

        // A lower budget read back than the one written is a simultaneous attempt's, and is kept; the one read
        // before, or none, means the write did not stick.
        $stored = $this->write($preAuthorizedCodeId, $left - 1, $expiresAt);
        $leftNow = $this->read($preAuthorizedCodeId);
        if (!$stored || $leftNow === null || $leftNow >= $left) {
            throw new RuntimeException(
                'Unable to count the transaction code attempt: the protocol cache did not keep the count.',
            );
        }

        return true;
    }


    /**
     * Whether attempts are counted: there is a protocol cache, and it keeps entries from one request to the next.
     */
    protected function isInForce(): bool
    {
        return $this->protocolCache instanceof ProtocolCache &&
        $this->moduleConfig->isProtocolCacheKeptAcrossRequests();
    }


    /**
     * The attempts left, or null when the cache answers with nothing which is a number.
     *
     * @throws \Psr\SimpleCache\InvalidArgumentException
     */
    protected function read(string $preAuthorizedCodeId): ?int
    {
        /** @var mixed $left */
        $left = $this->protocolCache?->get(null, ...$this->keyElements($preAuthorizedCodeId));

        return is_numeric($left) ? (int)$left : null;
    }


    /**
     * Whether the cache reports the budget as stored.
     *
     * @throws \Psr\SimpleCache\InvalidArgumentException
     */
    protected function write(string $preAuthorizedCodeId, int $left, DateTimeInterface $expiresAt): bool
    {
        return $this->protocolCache?->set(
            $left,
            max(1, $this->helpers->dateTime()->getSecondsToExpirationTime($expiresAt->getTimestamp())) +
            self::TTL_MARGIN_SECONDS,
            ...$this->keyElements($preAuthorizedCodeId),
        ) ?? false;
    }


    /**
     * Hashed, since the pre-authorized code is a bearer secret, which a cache key is no place for.
     *
     * @return string[]
     */
    protected function keyElements(string $preAuthorizedCodeId): array
    {
        return [self::CACHE_KEY, hash('sha256', $preAuthorizedCodeId)];
    }
}
