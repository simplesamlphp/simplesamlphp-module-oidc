<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\StatusList;

use DateTimeImmutable;
use DateTimeZone;
use Jose\Component\Core\JWK;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Codebooks\StatusListExpiryLaneEnum;
use SimpleSAML\Module\oidc\Codebooks\StatusListKeyProfileEnum;
use SimpleSAML\Module\oidc\Exceptions\StatusListException;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\StatusListEntryRepository;
use SimpleSAML\Module\oidc\Repositories\StatusListRepository;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\StatusList\DbStatusListTokenProvider;
use SimpleSAML\Module\oidc\StatusList\StatusListContentHasher;
use SimpleSAML\Module\oidc\StatusList\StatusListKeyResolver;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListRecord;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListTokenResult;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Did;
use SimpleSAML\OpenID\Did\DidJwkResolver;
use SimpleSAML\OpenID\Helpers as OpenIdHelpers;
use SimpleSAML\OpenID\Jwk\JwkDecorator;
use SimpleSAML\OpenID\TokenStatusList;
use SimpleSAML\OpenID\TokenStatusList\Factories\StatusListFactory;
use SimpleSAML\OpenID\TokenStatusList\Factories\StatusListTokenFactory;
use SimpleSAML\OpenID\TokenStatusList\StatusListToken;
use SimpleSAML\OpenID\ValueAbstracts\KeyPair;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPair;

#[CoversClass(DbStatusListTokenProvider::class)]
class DbStatusListTokenProviderTest extends TestCase
{
    protected const string LIST_ID = 'a-status-list-id';

    protected const string LIST_URI = 'https://op.example.org/module.php/oidc/statuslist/a-status-list-id';

    protected const string SIGNING_KEY_ID = 'vci-signing-key';

    protected const string DID_JWK = 'did:jwk:eyJrdHkiOiJFQyJ9';

    protected const string SIGNED_TOKEN = 'freshly.signed.token';

    protected const string PUBLISHED_TOKEN = 'already.published.token';

    protected MockObject $statusListRepositoryMock;
    protected MockObject $statusListEntryRepositoryMock;
    protected MockObject $statusListKeyResolverMock;
    protected MockObject $statusListTokenFactoryMock;
    protected MockObject $moduleConfigMock;
    protected MockObject $didJwkResolverMock;
    protected MockObject $loggerServiceMock;
    protected StatusListContentHasher $statusListContentHasher;
    protected Helpers $helpers;

    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->statusListRepositoryMock = $this->createMock(StatusListRepository::class);
        $this->statusListEntryRepositoryMock = $this->createMock(StatusListEntryRepository::class);
        $this->statusListContentHasher = new StatusListContentHasher();
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        $this->helpers = new Helpers();

        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getIssuer')->willReturn('https://op.example.org');

        $this->statusListKeyResolverMock = $this->createMock(StatusListKeyResolver::class);
        $this->statusListKeyResolverMock->method('getByKeyId')->willReturn($this->signatureKeyPair());

        $this->statusListTokenFactoryMock = $this->createMock(StatusListTokenFactory::class);
        $this->statusListTokenFactoryMock->method('forStatusList')->willReturn($this->signedTokenStub());

        $this->didJwkResolverMock = $this->createMock(DidJwkResolver::class);
        $this->didJwkResolverMock->method('generateDidJwkFromJwk')->willReturn(self::DID_JWK);
    }

    /**
     * Assembled here rather than in setUp so that a test can put its own token factory in place first,
     * which is the only way to assert what a token was signed over: a second stub of an already stubbed
     * method never gets reached.
     *
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    protected function sut(): DbStatusListTokenProvider
    {
        $didMock = $this->createMock(Did::class);
        $didMock->method('didJwkResolver')->willReturn($this->didJwkResolverMock);

        $tokenStatusListMock = $this->createMock(TokenStatusList::class);
        $tokenStatusListMock->method('statusListFactory')
            ->willReturn(new StatusListFactory(new OpenIdHelpers()));
        $tokenStatusListMock->method('statusListTokenFactory')
            ->willReturn($this->statusListTokenFactoryMock);

        return new DbStatusListTokenProvider(
            $this->statusListRepositoryMock,
            $this->statusListEntryRepositoryMock,
            $this->statusListContentHasher,
            $this->statusListKeyResolverMock,
            $tokenStatusListMock,
            $this->moduleConfigMock,
            $didMock,
            $this->helpers,
            $this->loggerServiceMock,
        );
    }

    /**
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    protected function signatureKeyPair(): SignatureKeyPair
    {
        $publicKey = $this->createMock(JwkDecorator::class);
        $publicKey->method('jwk')->willReturn(new JWK(['kty' => 'EC', 'crv' => 'P-256', 'x' => 'x', 'y' => 'y']));

        $keyPair = $this->createMock(KeyPair::class);
        $keyPair->method('getKeyId')->willReturn(self::SIGNING_KEY_ID);
        $keyPair->method('getPrivateKey')->willReturn($this->createMock(JwkDecorator::class));
        $keyPair->method('getPublicKey')->willReturn($publicKey);

        $signatureKeyPair = $this->createMock(SignatureKeyPair::class);
        $signatureKeyPair->method('getKeyPair')->willReturn($keyPair);
        $signatureKeyPair->method('getSignatureAlgorithm')->willReturn(SignatureAlgorithmEnum::RS256);

        return $signatureKeyPair;
    }

    /**
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    protected function signedTokenStub(): StatusListToken
    {
        $statusListToken = $this->createMock(StatusListToken::class);
        $statusListToken->method('getToken')->willReturn(self::SIGNED_TOKEN);

        return $statusListToken;
    }

    /**
     * @throws \Exception
     */
    protected function record(
        ?string $signedToken = null,
        string $signedTokenContentHash = '',
        ?string $signedTokenIssuedAt = null,
        ?string $signedTokenExpiresAt = null,
        ?string $retiredAt = null,
        StatusListKeyProfileEnum $keyProfile = StatusListKeyProfileEnum::DidJwk,
        int $invalidationCounter = 4,
    ): StatusListRecord {
        return new StatusListRecord(
            self::LIST_ID,
            self::LIST_URI,
            'default',
            'a-policy-fingerprint',
            StatusListExpiryLaneEnum::Expiring,
            1,
            2,
            64,
            '0,1,2',
            43200,
            604800,
            3600,
            self::SIGNING_KEY_ID,
            $keyProfile,
            0,
            true,
            null,
            $this->moment($retiredAt),
            $signedToken,
            $signedTokenContentHash,
            $this->moment($signedTokenIssuedAt),
            $this->moment($signedTokenExpiresAt),
            $this->moment('now'),
            $invalidationCounter,
        );
    }

    /**
     * @throws \Exception
     */
    protected function moment(?string $moment): ?DateTimeImmutable
    {
        return $moment === null ? null : new DateTimeImmutable($moment, new DateTimeZone('UTC'));
    }

    /**
     * @param array<int,int> $statuses
     */
    protected function contentHashFor(array $statuses): string
    {
        return $this->statusListContentHasher->hash(2, 64, $statuses);
    }

    /**
     * A published token signed just now, with its full life ahead of it.
     *
     * @param array<int,int> $statuses
     * @throws \Exception
     */
    protected function freshlyPublishedRecord(array $statuses = []): StatusListRecord
    {
        return $this->record(
            self::PUBLISHED_TOKEN,
            $this->contentHashFor($statuses),
            'now',
            '+7 days',
        );
    }

    /**
     * @throws \Exception
     */
    public function testReturnsNothingForAnUnknownList(): void
    {
        $this->statusListRepositoryMock->method('findById')->willReturn(null);

        $this->assertNull($this->sut()->getToken(self::LIST_ID));
    }

    /**
     * Retirement, not deactivation, is what ends publication: a list stops taking new credentials long
     * before the ones already in it stop needing a status.
     *
     * @throws \Exception
     */
    public function testReturnsNothingForARetiredList(): void
    {
        $this->statusListRepositoryMock->method('findById')
            ->willReturn($this->record(self::PUBLISHED_TOKEN, 'a-hash', 'now', '+7 days', 'now'));

        $this->assertNull($this->sut()->getToken(self::LIST_ID));
    }

    /**
     * The common path: one row is read and nothing else, which is what makes serving a list of a hundred
     * thousand entries cheap.
     *
     * @throws \Exception
     */
    public function testServesThePublishedTokenWithoutReadingTheEntries(): void
    {
        $this->statusListRepositoryMock->method('findById')->willReturn($this->freshlyPublishedRecord());
        $this->statusListEntryRepositoryMock->expects($this->never())->method('findNonValidStatuses');
        $this->statusListRepositoryMock->expects($this->never())->method('publishToken');

        $result = $this->sut()->getToken(self::LIST_ID);

        $this->assertInstanceOf(StatusListTokenResult::class, $result);
        $this->assertSame(self::PUBLISHED_TOKEN, $result->getToken());
        $this->assertSame(43200, $result->getTtlSeconds());
    }

    /**
     * @return array<string,array{?string,string,?string,?string}>
     */
    public static function staleTokens(): array
    {
        return [
            'never published' => [null, '', null, null],
            'invalidated by a status change' => [self::PUBLISHED_TOKEN, '', 'now', '+7 days'],
            'older than the refresh interval' => [self::PUBLISHED_TOKEN, 'a-hash', '-2 hours', '+7 days'],
            'close to its own expiry' => [self::PUBLISHED_TOKEN, 'a-hash', 'now', '+5 minutes'],
            'already expired' => [self::PUBLISHED_TOKEN, 'a-hash', '-8 days', '-1 day'],
        ];
    }

    /**
     * @throws \Exception
     */
    #[DataProvider('staleTokens')]
    public function testPublishesAFreshTokenWhenThePublishedOneWillNotDo(
        ?string $signedToken,
        string $contentHash,
        ?string $issuedAt,
        ?string $expiresAt,
    ): void {
        $record = $this->record($signedToken, $contentHash, $issuedAt, $expiresAt);

        $this->statusListRepositoryMock->method('findById')->willReturn($record);
        $this->statusListRepositoryMock->method('findByIdOnPrimary')->willReturn($record);
        $this->statusListEntryRepositoryMock->method('findNonValidStatuses')->willReturn([5 => 1]);
        $this->statusListRepositoryMock->expects($this->once())->method('publishToken')->willReturn(true);

        $result = $this->sut()->getToken(self::LIST_ID);

        $this->assertInstanceOf(StatusListTokenResult::class, $result);
        $this->assertSame(self::SIGNED_TOKEN, $result->getToken());
    }

    /**
     * The compare-and-set has to be given the hash which was on the row, so that a signer whose snapshot
     * was superseded fails to publish rather than overwriting a newer token.
     *
     * @throws \Exception
     */
    public function testPublishesAgainstTheHashItObserved(): void
    {
        $observed = $this->contentHashFor([5 => 1]);
        $record = $this->record(self::PUBLISHED_TOKEN, $observed, '-2 hours', '+7 days');

        $this->statusListRepositoryMock->method('findById')->willReturn($record);
        $this->statusListRepositoryMock->method('findByIdOnPrimary')->willReturn($record);
        $this->statusListEntryRepositoryMock->method('findNonValidStatuses')->willReturn([5 => 1]);

        $this->statusListRepositoryMock->expects($this->once())->method('publishToken')
            ->with(self::LIST_ID, $observed, 4, $observed, self::SIGNED_TOKEN)
            ->willReturn(true);

        $this->assertInstanceOf(StatusListTokenResult::class, $this->sut()->getToken(self::LIST_ID));
    }

    /**
     * While the content hash is empty it cannot settle publication on its own: an invalidation arriving
     * after this signer took its snapshot finds the hash already empty and leaves it empty, so the
     * signer would still match and publish a token built before that revocation -- with nothing left to
     * clear it. The counter is what the compare-and-set has to distinguish them by.
     *
     * @throws \Exception
     */
    public function testPublishesAgainstTheInvalidationCounterItObserved(): void
    {
        $record = $this->record(self::PUBLISHED_TOKEN, '', 'now', '+7 days', invalidationCounter: 9);

        $this->statusListRepositoryMock->method('findById')->willReturn($record);
        $this->statusListRepositoryMock->method('findByIdOnPrimary')->willReturn($record);
        $this->statusListEntryRepositoryMock->method('findNonValidStatuses')->willReturn([]);

        $this->statusListRepositoryMock->expects($this->once())->method('publishToken')
            ->with(self::LIST_ID, '', 9)
            ->willReturn(true);

        $this->assertInstanceOf(StatusListTokenResult::class, $this->sut()->getToken(self::LIST_ID));
    }

    /**
     * Fail closed. A token signed with a key the credential's holder never bound to is not one they can
     * verify, and reaching for the current key instead would look like success.
     *
     * @throws \Exception
     */
    public function testFailsWhenTheListsSigningKeyIsGone(): void
    {
        $record = $this->record();
        $this->statusListRepositoryMock->method('findById')->willReturn($record);
        $this->statusListRepositoryMock->method('findByIdOnPrimary')->willReturn($record);
        $this->statusListEntryRepositoryMock->method('findNonValidStatuses')->willReturn([]);

        $keyResolver = $this->createMock(StatusListKeyResolver::class);
        $keyResolver->method('getByKeyId')->willThrowException(new StatusListException('key is gone'));
        $this->statusListKeyResolverMock = $keyResolver;

        $this->statusListRepositoryMock->expects($this->never())->method('publishToken');

        $this->expectException(StatusListException::class);

        $this->sut()->getToken(self::LIST_ID);
    }

    /**
     * A revocation landing while the token is being signed is not visible to the compare-and-set, which
     * looks at the list row rather than at the entries. Re-reading them is what catches it.
     *
     * @throws \Exception
     */
    public function testDiscardsATokenSupersededWhileItWasBeingSigned(): void
    {
        $record = $this->record();
        $this->statusListRepositoryMock->method('findById')->willReturn($record);
        $this->statusListRepositoryMock->method('findByIdOnPrimary')->willReturn($record);

        // Each pass reads the entries twice, and here the second read differs from the first every time.
        $this->statusListEntryRepositoryMock->method('findNonValidStatuses')
            ->willReturnOnConsecutiveCalls(
                [],
                [5 => 1],
                [5 => 1],
                [5 => 1, 6 => 1],
                [5 => 1, 6 => 1],
                [5 => 1, 6 => 1, 7 => 1],
            );

        $this->statusListRepositoryMock->expects($this->never())->method('publishToken');

        $this->expectException(StatusListException::class);
        $this->expectExceptionMessageMatches('/kept changing/');

        $this->sut()->getToken(self::LIST_ID);
    }

    /**
     * Losing the race is not a failure. The winner's token describes the same list, so it is served
     * rather than signed again.
     *
     * @throws \Exception
     */
    public function testServesTheTokenAnotherRequestPublishedFirst(): void
    {
        $this->statusListRepositoryMock->method('findById')->willReturn($this->record());
        $this->statusListRepositoryMock->method('findByIdOnPrimary')
            ->willReturnOnConsecutiveCalls($this->record(), $this->freshlyPublishedRecord());
        $this->statusListEntryRepositoryMock->method('findNonValidStatuses')->willReturn([]);
        $this->statusListRepositoryMock->expects($this->once())->method('publishToken')->willReturn(false);

        $result = $this->sut()->getToken(self::LIST_ID);

        $this->assertInstanceOf(StatusListTokenResult::class, $result);
        $this->assertSame(self::PUBLISHED_TOKEN, $result->getToken());
    }

    /**
     * A list retired between the read which decided to re-sign and the authoritative one is gone, not
     * broken.
     *
     * @throws \Exception
     */
    public function testReturnsNothingWhenTheListIsRetiredWhileRepublishing(): void
    {
        $this->statusListRepositoryMock->method('findById')->willReturn($this->record());
        $this->statusListRepositoryMock->method('findByIdOnPrimary')
            ->willReturn($this->record(null, '', null, null, 'now'));

        $this->assertNull($this->sut()->getToken(self::LIST_ID));
    }

    /**
     * The token has to name the list by the URI which was stored, since a Relying Party compares it byte
     * for byte with the one its credential carries.
     *
     * @throws \Exception
     */
    public function testSignsWithTheStoredUriAndTheDidJwkIdentity(): void
    {
        $this->givenAListWhichNeedsPublishing();
        $this->statusListTokenFactoryMock = $this->createMock(StatusListTokenFactory::class);

        $this->statusListTokenFactoryMock->expects($this->once())->method('forStatusList')
            ->with(
                $this->anything(),
                self::LIST_URI,
                $this->anything(),
                SignatureAlgorithmEnum::RS256,
                $this->anything(),
                $this->anything(),
                $this->anything(),
                self::DID_JWK,
                [],
                ['kid' => self::DID_JWK . '#0'],
            )
            ->willReturn($this->signedTokenStub());

        $this->sut()->getToken(self::LIST_ID);
    }

    /**
     * Under the JWKS profile the key is resolved through the issuer's published key set instead, so the
     * token names the issuer and the plain key identifier.
     *
     * @throws \Exception
     */
    public function testSignsWithTheIssuerAndKeyIdUnderTheJwksProfile(): void
    {
        $this->givenAListWhichNeedsPublishing(StatusListKeyProfileEnum::Jwks);
        $this->statusListTokenFactoryMock = $this->createMock(StatusListTokenFactory::class);

        $this->statusListTokenFactoryMock->expects($this->once())->method('forStatusList')
            ->with(
                $this->anything(),
                self::LIST_URI,
                $this->anything(),
                $this->anything(),
                $this->anything(),
                $this->anything(),
                $this->anything(),
                'https://op.example.org',
                [],
                ['kid' => self::SIGNING_KEY_ID],
            )
            ->willReturn($this->signedTokenStub());

        $this->sut()->getToken(self::LIST_ID);
    }

    /**
     * @throws \Exception
     */
    protected function givenAListWhichNeedsPublishing(
        StatusListKeyProfileEnum $keyProfile = StatusListKeyProfileEnum::DidJwk,
    ): void {
        $record = $this->record(keyProfile: $keyProfile);

        $this->statusListRepositoryMock->method('findById')->willReturn($record);
        $this->statusListRepositoryMock->method('findByIdOnPrimary')->willReturn($record);
        $this->statusListEntryRepositoryMock->method('findNonValidStatuses')->willReturn([]);
        $this->statusListRepositoryMock->method('publishToken')->willReturn(true);
    }
}
