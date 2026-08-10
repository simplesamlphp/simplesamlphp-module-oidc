<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\ModuleConfig;

/**
 * Keeps the conformance stack's outbound destination allow-list in step with the clients seeded into it.
 *
 * Every destination in that stack is container-local and resolves to a private address, so the outbound
 * destination policy refuses all of them unless they are named in the configuration. The seeded clients
 * are the only place a destination is written down in the repository - the rest are handed to the OP by
 * the suite at runtime - which makes this pairing checkable, and worth checking: a refused destination
 * does not surface as a failed conformance check. The request is simply never made, so the suite waits
 * for a callback that is not coming and the plan ends incomplete with nothing failed, several minutes and
 * one full Docker stack later. That is what happened when the back-channel logout host was left out.
 */
#[CoversNothing]
class ConformanceConfigTest extends TestCase
{
    /**
     * Path fragments naming a URI the OP fetches or posts to. `redirect_uris` are deliberately absent:
     * the OP compares them and sends the browser there, so they are never an outbound request of its own.
     *
     * @var list<string>
     */
    protected const array OUTBOUND_URI_MARKERS = [
        'backchannel_logout',
        'jwks',
    ];

    /** @var array<string,mixed> */
    protected array $conformanceConfig;

    protected string $seedData;

    protected function setUp(): void
    {
        $repositoryRoot = dirname(__DIR__, 3);

        // Follows the SimpleSAMLphp convention of assigning $config instead of returning it, so include
        // it for that side effect and pick the variable up.
        require $repositoryRoot . '/docker/ssp/module_oidc.php';
        /** @var array<string,mixed> $config */
        $this->conformanceConfig = $config;

        $this->seedData = (string)file_get_contents($repositoryRoot . '/docker/conformance.sql');
    }

    public function testSeededOutboundDestinationsAreAllowed(): void
    {
        $allowedHosts = $this->allowedHosts();
        $destinationHosts = $this->seededOutboundHosts();

        // Without this the test would keep passing if the extraction below ever stopped matching anything,
        // which is the failure mode a test of this shape has: it would report the allow-list as complete
        // precisely because it had found nothing to hold it to.
        $this->assertNotEmpty(
            $destinationHosts,
            'No outbound destination could be read out of docker/conformance.sql, so this test is ' .
            'checking nothing. Either the seeded clients no longer carry one, or the URIs are written in ' .
            'a form this test does not recognise.',
        );

        foreach ($destinationHosts as $host) {
            $this->assertContains(
                $host,
                $allowedHosts,
                sprintf(
                    'A client seeded in docker/conformance.sql makes the OP send a request to %s, which ' .
                    'is not named in %s in docker/ssp/module_oidc.php. Every destination in this stack ' .
                    'resolves privately, so the outbound destination policy refuses it and the request is ' .
                    'never made.',
                    $host,
                    'ModuleConfig::OPTION_OUTBOUND_ALLOWED_HOSTS',
                ),
            );
        }
    }

    /**
     * @return list<string>
     */
    protected function allowedHosts(): array
    {
        /** @var list<string> $allowedHosts */
        $allowedHosts = $this->conformanceConfig[ModuleConfig::OPTION_OUTBOUND_ALLOWED_HOSTS] ?? [];

        return array_map($this->normalizeHost(...), $allowedHosts);
    }

    /**
     * The hosts of the URIs seeded clients cause the OP to make an outbound request to.
     *
     * @return list<string>
     */
    protected function seededOutboundHosts(): array
    {
        // Comments describe what the seed does rather than being part of it, and one of them quotes a URL.
        // Reading destinations out of them would hold the allow-list to a host that prose mentions, which
        // may be one the data no longer names.
        $statements = (string)preg_replace('/^\s*--.*$/m', '', $this->seedData);

        // Some columns hold JSON, where a URL is written with escaped slashes.
        $statements = str_replace('\/', '/', $statements);

        preg_match_all('#https?://[^\s\'"(),;]+#i', $statements, $matches);

        $hosts = [];

        foreach ($matches[0] as $uri) {
            if (!$this->isOutboundUri($uri)) {
                continue;
            }

            $host = parse_url($uri, PHP_URL_HOST);

            if (is_string($host) && $host !== '') {
                $hosts[] = $this->normalizeHost($host);
            }
        }

        return array_values(array_unique($hosts));
    }

    protected function isOutboundUri(string $uri): bool
    {
        $path = parse_url($uri, PHP_URL_PATH);

        if (!is_string($path)) {
            return false;
        }

        foreach (self::OUTBOUND_URI_MARKERS as $marker) {
            if (str_contains(strtolower($path), $marker)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Matches how the destination policy compares a host: case and a trailing root label carry no meaning.
     */
    protected function normalizeHost(string $host): string
    {
        return rtrim(strtolower(trim($host)), '.');
    }
}
