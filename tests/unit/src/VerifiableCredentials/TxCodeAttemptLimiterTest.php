<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\VerifiableCredentials;

use ArrayObject;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Cache\CacheItemInterface;
use RuntimeException;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Helpers\DateTime;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;
use SimpleSAML\Module\oidc\VerifiableCredentials\TxCodeAttemptLimiter;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Cache\Adapter\ChainAdapter;
use Symfony\Component\Cache\Adapter\NullAdapter;
use Symfony\Component\Cache\CacheItem;
use Symfony\Component\Cache\Psr16Cache;

/**
 * The budget of attempts at one pre-authorized code's Transaction Code, kept in the protocol cache: opened at the
 * configured limit when the code is created, spent one attempt at a time, and refused once spent; each code has a
 * budget of its own, kept until the code expires and a minute more, under a key which does not hold the code.
 * A budget which is not on record -- never opened, evicted, unreadable -- refuses the attempt rather than count
 * as a fresh one. Without a protocol cache, or with one which keeps nothing from one request to the next, nothing
 * is kept and every attempt is admitted. A cache which throws is
 * let through, and one which does not keep a write -- as Symfony's adapters do when their backend fails -- gets
 * an exception, whether the cache reports the write as not stored or the budget does not read back as written.
 * Most tests use a double which keeps what it is given; the ones about a real cache use Symfony's.
 */
#[CoversClass(TxCodeAttemptLimiter::class)]
#[AllowMockObjectsWithoutExpectations]
class TxCodeAttemptLimiterTest extends TestCase
{
    private const string CODE = 'pre-authorized-code-secret';

    private const string OTHER_CODE = 'another-pre-authorized-code';


    private ModuleConfig&MockObject $moduleConfigMock;

    private ProtocolCache&MockObject $protocolCacheMock;

    private Helpers&MockObject $helpersMock;

    private DateTime&MockObject $dateTimeHelperMock;

    private LoggerService&MockObject $loggerServiceMock;

    /** @var array<string,mixed> What the cache holds, by its key elements joined. */
    private array $cached = [];

    /** @var int[] The lifetime of every write, in order. */
    private array $ttls = [];

    /** @var array<int, array{level: string, message: string}> */
    private array $logRecords = [];


    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getVciTxCodeMaxAttempts')->willReturn(3);
        $this->moduleConfigMock->method('isProtocolCacheKeptAcrossRequests')->willReturn(true);
        $this->dateTimeHelperMock = $this->createMock(DateTime::class);
        $this->dateTimeHelperMock->method('getSecondsToExpirationTime')->willReturn(600);
        $this->helpersMock = $this->createMock(Helpers::class);
        $this->helpersMock->method('dateTime')->willReturn($this->dateTimeHelperMock);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        foreach (['debug', 'warning'] as $level) {
            $this->loggerServiceMock->method($level)->willReturnCallback(
                function (string $message) use ($level): void {
                    $this->logRecords[] = ['level' => $level, 'message' => $message];
                },
            );
        }

        // Stands in for a cache which keeps what it is given, so that spending can be observed across calls.
        $this->protocolCacheMock = $this->createMock(ProtocolCache::class);
        $this->protocolCacheMock->method('get')->willReturnCallback(
            fn(mixed $default, string ...$keyElements): mixed => $this->cached[implode('|', $keyElements)] ?? $default,
        );
        $this->protocolCacheMock->method('set')->willReturnCallback(
            function (mixed $value, int $ttl, string ...$keyElements): bool {
                $this->cached[implode('|', $keyElements)] = $value;
                $this->ttls[] = $ttl;

                return true;
            },
        );
    }


    private function sut(?ProtocolCache $protocolCache = null, bool $withoutCache = false): TxCodeAttemptLimiter
    {
        return new TxCodeAttemptLimiter(
            $this->moduleConfigMock,
            $withoutCache ? null : ($protocolCache ?? $this->protocolCacheMock),
            $this->helpersMock,
            $this->loggerServiceMock,
        );
    }


    private function expiresAt(): DateTimeImmutable
    {
        return new DateTimeImmutable('+10 minutes');
    }


    /**
     * A Symfony cache whose backend can be made to fail: a failed write is reported as not done and a failed
     * read is answered with a miss, as Symfony's adapters do, which log the failure rather than throw.
     *
     * @param \ArrayObject<string,bool> $fail Its 'reads' and 'writes' switches.
     */
    private function flakyCache(ArrayObject $fail): ProtocolCache
    {
        return new ProtocolCache(new Psr16Cache($this->flakyAdapter($fail)));
    }


    /**
     * @param \ArrayObject<string,bool> $fail Its 'reads' and 'writes' switches.
     */
    private function flakyAdapter(ArrayObject $fail): ArrayAdapter
    {
        return new class ($fail) extends ArrayAdapter {
            /** @param \ArrayObject<string,bool> $fail */
            public function __construct(private readonly ArrayObject $fail)
            {
                parent::__construct();
            }


            public function save(CacheItemInterface $item): bool
            {
                return $this->fail['writes'] ? false : parent::save($item);
            }


            public function getItem(mixed $key): CacheItem
            {
                return parent::getItem($this->fail['reads'] ? 'unreadable' : $key);
            }
        };
    }


    public function testOpensABudgetOfTheConfiguredLimit(): void
    {
        $this->sut()->open(self::CODE, $this->expiresAt());

        $this->assertSame([3], array_values($this->cached));
    }


    public function testAdmitsUntilTheBudgetIsSpentAndThenRefuses(): void
    {
        $sut = $this->sut();
        $sut->open(self::CODE, $this->expiresAt());

        $this->assertTrue($sut->admitAttempt(self::CODE, $this->expiresAt()));
        $this->assertTrue($sut->admitAttempt(self::CODE, $this->expiresAt()));
        $this->assertTrue($sut->admitAttempt(self::CODE, $this->expiresAt()));
        $this->assertFalse($sut->admitAttempt(self::CODE, $this->expiresAt()));
        $this->assertFalse($sut->admitAttempt(self::CODE, $this->expiresAt()));
    }


    public function testKeepsABudgetForEachCode(): void
    {
        $sut = $this->sut();
        $sut->open(self::CODE, $this->expiresAt());
        $sut->open(self::OTHER_CODE, $this->expiresAt());

        foreach (range(1, 3) as $ignored) {
            $sut->admitAttempt(self::CODE, $this->expiresAt());
        }

        $this->assertFalse($sut->admitAttempt(self::CODE, $this->expiresAt()));
        $this->assertTrue($sut->admitAttempt(self::OTHER_CODE, $this->expiresAt()));
    }


    public function testALimitOfOneAdmitsOneAttempt(): void
    {
        $moduleConfig = $this->createMock(ModuleConfig::class);
        $moduleConfig->method('getVciTxCodeMaxAttempts')->willReturn(1);
        $moduleConfig->method('isProtocolCacheKeptAcrossRequests')->willReturn(true);
        $this->moduleConfigMock = $moduleConfig;
        $sut = $this->sut();
        $sut->open(self::CODE, $this->expiresAt());

        $this->assertTrue($sut->admitAttempt(self::CODE, $this->expiresAt()));
        $this->assertFalse($sut->admitAttempt(self::CODE, $this->expiresAt()));
    }


    /**
     * The limit is read when the budget is opened, so a code keeps the attempts it was given whatever the
     * configuration says by the time they are spent.
     */
    public function testSpendsTheBudgetTheCodeWasOpenedWith(): void
    {
        $this->sut()->open(self::CODE, $this->expiresAt());
        $moduleConfig = $this->createMock(ModuleConfig::class);
        $moduleConfig->expects($this->never())->method('getVciTxCodeMaxAttempts');
        $moduleConfig->method('isProtocolCacheKeptAcrossRequests')->willReturn(true);
        $this->moduleConfigMock = $moduleConfig;
        $sut = $this->sut();

        foreach (range(1, 3) as $ignored) {
            $this->assertTrue($sut->admitAttempt(self::CODE, $this->expiresAt()));
        }
        $this->assertFalse($sut->admitAttempt(self::CODE, $this->expiresAt()));
    }


    /**
     * The budget is kept for as long as the code can still be redeemed and a minute more, so that it does not
     * go before the code does; a code which expired a moment ago still gets a budget which outlives it.
     *
     * @return array<string,array{int, int}>
     */
    public static function lifetimeProvider(): array
    {
        return [
            'ten minutes left' => [600, 660],
            'one second left' => [1, 61],
            'expired a moment ago' => [-5, 61],
        ];
    }


    #[DataProvider('lifetimeProvider')]
    public function testKeepsTheBudgetUntilTheCodeExpiresAndAMinuteMore(int $secondsLeft, int $expectedTtl): void
    {
        $expiresAt = $this->expiresAt();
        $dateTimeHelper = $this->createMock(DateTime::class);
        $dateTimeHelper->expects($this->exactly(2))
            ->method('getSecondsToExpirationTime')
            ->with($expiresAt->getTimestamp())
            ->willReturn($secondsLeft);
        $this->helpersMock = $this->createMock(Helpers::class);
        $this->helpersMock->method('dateTime')->willReturn($dateTimeHelper);
        $sut = $this->sut();

        $sut->open(self::CODE, $expiresAt);
        $sut->admitAttempt(self::CODE, $expiresAt);

        $this->assertSame([$expectedTtl, $expectedTtl], $this->ttls);
    }


    /**
     * The pre-authorized code is a bearer secret; the budget needs it only to tell one code from another.
     */
    public function testDoesNotKeepTheCodeInTheCache(): void
    {
        $sut = $this->sut();
        $sut->open(self::CODE, $this->expiresAt());
        $sut->admitAttempt(self::CODE, $this->expiresAt());

        $this->assertNotEmpty($this->cached);
        foreach (array_keys($this->cached) as $key) {
            $this->assertStringNotContainsString(self::CODE, $key);
        }
    }


    /**
     * A budget which is not on record was never opened, was evicted, or could not be read; counting it as a
     * fresh budget would hand out attempts a lost record never gave, so the attempt is refused.
     *
     * @return array<string,array{?string}>
     */
    public static function noBudgetOnRecordProvider(): array
    {
        return [
            'nothing on record' => [null],
            'something which is not a number' => ['not a number'],
        ];
    }


    #[DataProvider('noBudgetOnRecordProvider')]
    public function testRefusesAnAttemptWhenNoBudgetIsOnRecord(?string $onRecord): void
    {
        $sut = $this->sut();
        if ($onRecord !== null) {
            $sut->open(self::CODE, $this->expiresAt());
            $this->cached[(string)array_key_first($this->cached)] = $onRecord;
        }
        $written = count($this->ttls);

        $this->assertFalse($sut->admitAttempt(self::CODE, $this->expiresAt()));
        $this->assertCount($written, $this->ttls, 'Nothing is written for an attempt which is refused.');
        $this->assertContains(
            [
                'level' => 'warning',
                'message' => 'No transaction code attempts are on record for the pre-authorized code, so none is ' .
                    'admitted: its record was lost from the protocol cache, could not be read, or was never made.',
            ],
            $this->logRecords,
        );
    }


    /**
     * A budget at or below nothing is spent, however it came to be below nothing.
     *
     * @return array<string,array{int}>
     */
    public static function spentBudgetProvider(): array
    {
        return [
            'none left' => [0],
            'fewer than none' => [-1],
        ];
    }


    #[DataProvider('spentBudgetProvider')]
    public function testRefusesAnAttemptWhenNoneIsLeft(int $left): void
    {
        $protocolCache = $this->createMock(ProtocolCache::class);
        $protocolCache->method('get')->willReturn($left);
        $protocolCache->expects($this->never())->method('set');

        $this->assertFalse($this->sut($protocolCache)->admitAttempt(self::CODE, $this->expiresAt()));
    }


    /**
     * Without a protocol cache the limit is not in force: no budget, and every attempt goes ahead.
     */
    public function testAdmitsEveryAttemptWithoutAProtocolCache(): void
    {
        $this->moduleConfigMock->expects($this->never())->method('getVciTxCodeMaxAttempts');
        $sut = $this->sut(withoutCache: true);

        $sut->open(self::CODE, $this->expiresAt());
        foreach (range(1, 10) as $ignored) {
            $this->assertTrue($sut->admitAttempt(self::CODE, $this->expiresAt()));
        }
        $this->assertSame([], $this->ttls);
        $this->assertContains(
            [
                'level' => 'debug',
                'message' => 'Transaction code attempts are not counted, since no protocol cache which keeps ' .
                    'entries across requests is configured.',
            ],
            $this->logRecords,
        );
        $this->assertNotContains('warning', array_column($this->logRecords, 'level'));
    }


    /**
     * A protocol cache which keeps nothing from one request to the next would lose the budget between the offer
     * and the token request, and so refuse every code; it counts as no cache instead, with a warning when an
     * offer is made, since it is most likely a mistake.
     */
    public function testCountsNothingInACacheWhichKeepsNothingAcrossRequests(): void
    {
        $moduleConfig = $this->createMock(ModuleConfig::class);
        $moduleConfig->method('isProtocolCacheKeptAcrossRequests')->willReturn(false);
        $moduleConfig->expects($this->never())->method('getVciTxCodeMaxAttempts');
        $this->moduleConfigMock = $moduleConfig;
        $protocolCache = $this->createMock(ProtocolCache::class);
        $protocolCache->expects($this->never())->method('get');
        $protocolCache->expects($this->never())->method('set');
        $sut = $this->sut($protocolCache);

        $sut->open(self::CODE, $this->expiresAt());
        foreach (range(1, 10) as $ignored) {
            $this->assertTrue($sut->admitAttempt(self::CODE, $this->expiresAt()));
        }
        $this->assertContains(
            [
                'level' => 'warning',
                'message' => 'Transaction code attempts are not counted: the protocol cache adapter keeps nothing ' .
                    'from one request to the next.',
            ],
            $this->logRecords,
        );
    }


    /**
     * A configured cache is the deployment asking for the limit, so a cache which throws, reading the budget or
     * writing it, is let through rather than passed over.
     *
     * @return array<string,array{string, string}>
     */
    public static function failingCacheOperationProvider(): array
    {
        return [
            'opening, writing' => ['open', 'set'],
            'spending, reading' => ['admitAttempt', 'get'],
            'spending, writing' => ['admitAttempt', 'set'],
        ];
    }


    #[DataProvider('failingCacheOperationProvider')]
    public function testLetsACacheFailureThrough(string $limiterMethod, string $failingOperation): void
    {
        $protocolCache = $this->createMock(ProtocolCache::class);
        $failure = new RuntimeException('Cache is down.');
        if ($failingOperation === 'get') {
            $protocolCache->method('get')->willThrowException($failure);
        } else {
            $protocolCache->method('get')->willReturn(3);
            $protocolCache->method('set')->willThrowException($failure);
        }

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Cache is down.');

        $this->sut($protocolCache)->{$limiterMethod}(self::CODE, $this->expiresAt());
    }


    /**
     * Through the protocol cache the module builds, over a Symfony adapter: the budget is kept under the key the
     * cache decorator derives, and holds across limiters, as it does across requests.
     */
    public function testKeepsTheBudgetInASymfonyCache(): void
    {
        $protocolCache = new ProtocolCache(new Psr16Cache(new ArrayAdapter()));
        $this->sut($protocolCache)->open(self::CODE, $this->expiresAt());

        foreach (range(1, 3) as $ignored) {
            $this->assertTrue($this->sut($protocolCache)->admitAttempt(self::CODE, $this->expiresAt()));
        }

        $this->assertFalse($this->sut($protocolCache)->admitAttempt(self::CODE, $this->expiresAt()));
        $this->assertFalse(
            $this->sut($protocolCache)->admitAttempt(self::OTHER_CODE, $this->expiresAt()),
            'A code which was never given a budget has no attempts.',
        );
    }


    /**
     * A budget the cache does not keep, written but not done or written but not read back, would leave a code
     * which can never be redeemed, so creating the code fails instead.
     *
     * @return array<string,array{string}>
     */
    public static function failingSwitchProvider(): array
    {
        return [
            'a write which is not done' => ['writes'],
            'a read which misses' => ['reads'],
        ];
    }


    #[DataProvider('failingSwitchProvider')]
    public function testRefusesToOpenABudgetTheCacheDoesNotKeep(string $failing): void
    {
        $fail = new ArrayObject(['reads' => false, 'writes' => false]);
        $fail[$failing] = true;

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('the protocol cache did not keep them');

        $this->sut($this->flakyCache($fail))->open(self::CODE, $this->expiresAt());
    }


    /**
     * A spent attempt which the cache does not keep would leave the budget where it was, so the attempt is refused
     * with an exception rather than admitted.
     */
    public function testRefusesAnAttemptWhoseSpendingTheCacheDoesNotKeep(): void
    {
        $fail = new ArrayObject(['reads' => false, 'writes' => false]);
        $sut = $this->sut($this->flakyCache($fail));
        $sut->open(self::CODE, $this->expiresAt());
        $fail['writes'] = true;

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('the protocol cache did not keep the count');

        $sut->admitAttempt(self::CODE, $this->expiresAt());
    }


    /**
     * A read which fails is answered as a miss, which refuses that attempt; it neither spends one nor, for a code
     * whose budget is spent, gives any back.
     */
    public function testAFailedReadRefusesTheAttemptAndGivesNothingBack(): void
    {
        $fail = new ArrayObject(['reads' => false, 'writes' => false]);
        $sut = $this->sut($this->flakyCache($fail));
        $sut->open(self::CODE, $this->expiresAt());

        $fail['reads'] = true;
        $this->assertFalse($sut->admitAttempt(self::CODE, $this->expiresAt()));
        $fail['reads'] = false;

        foreach (range(1, 3) as $ignored) {
            $this->assertTrue($sut->admitAttempt(self::CODE, $this->expiresAt()));
        }

        $fail['reads'] = true;
        $this->assertFalse($sut->admitAttempt(self::CODE, $this->expiresAt()));
        $fail['reads'] = false;
        $this->assertFalse($sut->admitAttempt(self::CODE, $this->expiresAt()));
    }


    /**
     * A budget which reads back as it was before this attempt, or higher, or not at all, was not spent, though the
     * cache reported the write as stored.
     *
     * @return array<string,array{?int}>
     */
    public static function budgetNotSpentProvider(): array
    {
        return [
            'where it was' => [3],
            'higher' => [4],
            'not at all' => [null],
        ];
    }


    #[DataProvider('budgetNotSpentProvider')]
    public function testRefusesAnAttemptWhoseBudgetDoesNotReadBackSpent(?int $readBack): void
    {
        $protocolCache = $this->createMock(ProtocolCache::class);
        $protocolCache->method('get')->willReturnOnConsecutiveCalls(3, $readBack);
        $protocolCache->method('set')->willReturn(true);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('the protocol cache did not keep the count');

        $this->sut($protocolCache)->admitAttempt(self::CODE, $this->expiresAt());
    }


    /**
     * A write the cache reports as not stored is refused even when the value reads back as written: a chain of
     * adapters answers the read from a layer which stored it, while a layer which did not is what the next
     * request may read from.
     *
     * @return array<string,array{string, int[], string}>
     */
    public static function writeReportedAsNotStoredProvider(): array
    {
        return [
            'opening' => ['open', [3], 'the protocol cache did not keep them'],
            'spending' => ['admitAttempt', [3, 2], 'the protocol cache did not keep the count'],
        ];
    }


    /**
     * @param int[] $reads
     */
    #[DataProvider('writeReportedAsNotStoredProvider')]
    public function testRefusesAWriteTheCacheReportsAsNotStored(
        string $limiterMethod,
        array $reads,
        string $message,
    ): void {
        $protocolCache = $this->createMock(ProtocolCache::class);
        $protocolCache->method('get')->willReturnOnConsecutiveCalls(...$reads);
        $protocolCache->method('set')->willReturn(false);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage($message);

        $this->sut($protocolCache)->{$limiterMethod}(self::CODE, $this->expiresAt());
    }


    /**
     * The chain which a decrement held only in its memory layer would get past: each request starts with an empty
     * memory layer and reads the budget from the backend, so a backend which stops taking writes must refuse the
     * attempt, though the read-back, answered from memory, shows the budget spent.
     */
    public function testRefusesAnAttemptWhichAChainedBackendDidNotStore(): void
    {
        $fail = new ArrayObject(['reads' => false, 'writes' => false]);
        $backend = $this->flakyAdapter($fail);
        $request = fn(): TxCodeAttemptLimiter => $this->sut(
            new ProtocolCache(new Psr16Cache(new ChainAdapter([new ArrayAdapter(), $backend]))),
        );
        $request()->open(self::CODE, $this->expiresAt());
        $this->assertTrue($request()->admitAttempt(self::CODE, $this->expiresAt()));
        $fail['writes'] = true;

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('the protocol cache did not keep the count');

        $request()->admitAttempt(self::CODE, $this->expiresAt());
    }


    /**
     * An adapter which stores nothing but reports every write as done gives no code its attempts, so creating
     * the code fails, rather than every redemption of it. Named as the protocol cache adapter, the configuration
     * says what it is and attempts are not counted at all; inside an adapter built of others it does not, and
     * this is what is left.
     */
    public function testRefusesToOpenABudgetInACacheWhichKeepsNothing(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('the protocol cache did not keep them');

        $this->sut(new ProtocolCache(new Psr16Cache(new NullAdapter())))->open(self::CODE, $this->expiresAt());
    }


    /**
     * A budget lower than the one written is a simultaneous attempt's, kept by the cache, so this one was spent.
     */
    public function testAdmitsAnAttemptWhoseBudgetASimultaneousOneLowered(): void
    {
        $protocolCache = $this->createMock(ProtocolCache::class);
        $protocolCache->method('get')->willReturnOnConsecutiveCalls(3, 1);
        $protocolCache->method('set')->willReturn(true);

        $this->assertTrue($this->sut($protocolCache)->admitAttempt(self::CODE, $this->expiresAt()));
    }
}
