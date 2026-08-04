<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\StatusList;

use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;
use Throwable;

/**
 * A per-client ceiling on Status List requests.
 *
 * The endpoint is unauthenticated and returns a body which can reach a couple of hundred kilobytes, so
 * some way of bounding what one client can pull is worth having. What this is not is a security control:
 * it counts within a fixed minute rather than a sliding window, the counter is read and written as two
 * separate operations so simultaneous requests can both see the same value, and it needs a cache to be
 * configured at all. Every one of those errs towards letting a request through.
 *
 * That direction is chosen. Wrongly refusing here does not slow an attacker down, it makes credentials
 * in wallets unverifiable -- so where this is unsure, it permits.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\StatusList\StatusListRateLimiterTest
 */
class StatusListRateLimiter
{
    protected const string CACHE_KEY = 'status-list-requests';

    /** Public so that a caller refusing a request can tell the client when the window turns over. */
    final public const int WINDOW_SECONDS = 60;

    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly ?ProtocolCache $protocolCache,
        protected readonly Helpers $helpers,
        protected readonly LoggerService $loggerService,
    ) {
    }

    /**
     * @param ?string $clientIdentifier Whatever the request appears to come from, or null when that
     * could not be established -- in which case there is nothing to count against and the request goes
     * through.
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function allows(?string $clientIdentifier): bool
    {
        $limit = $this->moduleConfig->getVciStatusListRequestsPerMinute();

        if (
            $limit < 1 ||
            $clientIdentifier === null ||
            $clientIdentifier === '' ||
            !$this->protocolCache instanceof ProtocolCache
        ) {
            return true;
        }

        $window = intdiv($this->helpers->dateTime()->getUtc()->getTimestamp(), self::WINDOW_SECONDS);

        // Hashed, so that a record of who asked for what does not accumulate in the cache. The counter
        // needs the address only to tell one client from another, never to report it.
        $keyElements = [self::CACHE_KEY, (string)$window, hash('sha256', $clientIdentifier)];

        try {
            /** @var mixed $used */
            $used = $this->protocolCache->get(0, ...$keyElements);
            $used = is_numeric($used) ? (int)$used : 0;

            if ($used >= $limit) {
                return false;
            }

            // Held for two windows rather than one, since an entry written at the very end of a window
            // would otherwise be evicted while that window is still current on a slower clock.
            $this->protocolCache->set($used + 1, self::WINDOW_SECONDS * 2, ...$keyElements);
        } catch (Throwable $throwable) {
            // A cache which is down must not take a public endpoint down with it.
            $this->loggerService->warning(
                'Unable to apply the Status List rate limit, so the request was allowed: ' .
                $throwable->getMessage(),
            );

            return true;
        }

        return true;
    }
}
