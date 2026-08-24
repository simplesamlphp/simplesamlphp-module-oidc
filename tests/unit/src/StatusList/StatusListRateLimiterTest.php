<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\StatusList;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\StatusList\StatusListRateLimiter;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;

#[CoversClass(StatusListRateLimiter::class)]
#[AllowMockObjectsWithoutExpectations]
class StatusListRateLimiterTest extends TestCase
{
    protected MockObject $moduleConfigMock;

    protected MockObject $protocolCacheMock;

    protected MockObject $loggerServiceMock;

    protected Helpers $helpers;

    /** @var array<string,int> */
    protected array $cached = [];


    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getVciStatusListRequestsPerMinute')->willReturn(3);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        $this->helpers = new Helpers();

        // Stands in for a cache which actually keeps what it is given, so that counting can be observed
        // across calls rather than only asserted one call at a time.
        $this->protocolCacheMock = $this->createMock(ProtocolCache::class);
        $this->protocolCacheMock->method('get')->willReturnCallback(
            fn(mixed $default, string ...$keyElements): mixed =>
                $this->cached[implode('|', $keyElements)] ?? $default,
        );
        $this->protocolCacheMock->method('set')->willReturnCallback(
            function (mixed $value, mixed $ttl, string ...$keyElements): void {
                $this->cached[implode('|', $keyElements)] = (int)$value;
            },
        );
    }


    protected function sut(?ProtocolCache $protocolCache = null): StatusListRateLimiter
    {
        return new StatusListRateLimiter(
            $this->moduleConfigMock,
            $protocolCache ?? $this->protocolCacheMock,
            $this->helpers,
            $this->loggerServiceMock,
        );
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function testAllowsUpToTheLimitAndThenRefuses(): void
    {
        $sut = $this->sut();

        $this->assertTrue($sut->allows('198.51.100.7'));
        $this->assertTrue($sut->allows('198.51.100.7'));
        $this->assertTrue($sut->allows('198.51.100.7'));
        $this->assertFalse($sut->allows('198.51.100.7'));
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function testCountsEachClientSeparately(): void
    {
        $sut = $this->sut();

        foreach (range(1, 3) as $ignored) {
            $sut->allows('198.51.100.7');
        }

        $this->assertFalse($sut->allows('198.51.100.7'));
        $this->assertTrue($sut->allows('198.51.100.8'));
    }


    /**
     * The address is only needed to tell one client from another, never to report who asked for what.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function testDoesNotKeepTheClientAddressInTheCache(): void
    {
        $this->sut()->allows('198.51.100.7');

        $this->assertNotEmpty($this->cached);

        foreach (array_keys($this->cached) as $key) {
            $this->assertStringNotContainsString('198.51.100.7', $key);
        }
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function testAppliesNoLimitWhenNoneIsConfigured(): void
    {
        $moduleConfig = $this->createMock(ModuleConfig::class);
        $moduleConfig->method('getVciStatusListRequestsPerMinute')->willReturn(0);
        $this->moduleConfigMock = $moduleConfig;

        $sut = $this->sut();

        foreach (range(1, 10) as $ignored) {
            $this->assertTrue($sut->allows('198.51.100.7'));
        }
    }


    /**
     * Without somewhere to count, there is nothing to count -- and refusing on that basis would take a
     * public endpoint down for the sake of a limit which was never being applied anyway.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function testAllowsEverythingWithoutACache(): void
    {
        $sut = new StatusListRateLimiter(
            $this->moduleConfigMock,
            null,
            $this->helpers,
            $this->loggerServiceMock,
        );

        foreach (range(1, 10) as $ignored) {
            $this->assertTrue($sut->allows('198.51.100.7'));
        }
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function testAllowsWhenThereIsNothingToCountAgainst(): void
    {
        $this->assertTrue($this->sut()->allows(null));
        $this->assertTrue($this->sut()->allows(''));
    }


    /**
     * A cache which is down must not take the endpoint down with it.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function testAllowsWhenTheCacheFails(): void
    {
        $protocolCache = $this->createMock(ProtocolCache::class);
        $protocolCache->method('get')->willThrowException(new RuntimeException('cache is down'));

        $this->loggerServiceMock->expects($this->once())->method('warning');

        $this->assertTrue($this->sut($protocolCache)->allows('198.51.100.7'));
    }
}
