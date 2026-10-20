<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\StatusList;

use DateInterval;
use DateTimeImmutable;
use DateTimeZone;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SimpleSAML\Module\oidc\Codebooks\StatusListExpiryLaneEnum;
use SimpleSAML\Module\oidc\Codebooks\StatusListKeyProfileEnum;
use SimpleSAML\Module\oidc\Exceptions\StatusListException;
use SimpleSAML\Module\oidc\Factories\DidFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Helpers\DateTime as DateTimeHelper;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\StatusListEntryRepository;
use SimpleSAML\Module\oidc\Repositories\StatusListRepository;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\StatusList\DbStatusListTokenProvider;
use SimpleSAML\Module\oidc\StatusList\StatusListContentHasher;
use SimpleSAML\Module\oidc\StatusList\StatusListKeyResolver;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListRecord;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListTokenResult;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\VciCertificateChain;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmBag;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Did\DidJwkResolver;
use SimpleSAML\OpenID\Did\DidUrl;
use SimpleSAML\OpenID\Did\Factories\DidDocumentFactory;
use SimpleSAML\OpenID\Exceptions\StatusListException as LibraryStatusListException;
use SimpleSAML\OpenID\Helpers as OpenIdHelpers;
use SimpleSAML\OpenID\Jwk\Factories\JwkDecoratorFactory;
use SimpleSAML\OpenID\Jwk\JwkDecorator;
use SimpleSAML\OpenID\SupportedAlgorithms;
use SimpleSAML\OpenID\TokenStatusList;
use SimpleSAML\OpenID\TokenStatusList\Factories\StatusListFactory;
use SimpleSAML\OpenID\TokenStatusList\Factories\StatusListTokenFactory;
use SimpleSAML\OpenID\TokenStatusList\StatusListToken;
use SimpleSAML\OpenID\ValueAbstracts\KeyPair;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPair;
use SimpleSAML\OpenID\X509;
use SimpleSAML\Test\Module\oidc\unit\VerifiableCredentials\CertificateBuilder;

#[CoversClass(DbStatusListTokenProvider::class)]
#[AllowMockObjectsWithoutExpectations]
class DbStatusListTokenProviderTest extends TestCase
{
    protected const string LIST_ID = 'a-status-list-id';

    protected const string LIST_URI = 'https://op.example.org/module.php/oidc/statuslist/a-status-list-id';

    protected const string SIGNING_KEY_ID = 'vci-signing-key';

    protected const string DID_JWK = 'did:jwk:eyJrdHkiOiJFQyJ9';

    protected const string DID_WEB = 'did:web:issuer.example.org';

    protected const string SIGNED_TOKEN = 'freshly.signed.token';

    protected const string PUBLISHED_TOKEN = 'already.published.token';


    protected MockObject $statusListRepositoryMock;

    protected MockObject $statusListEntryRepositoryMock;

    protected MockObject $statusListKeyResolverMock;

    protected MockObject $statusListTokenFactoryMock;

    protected MockObject $moduleConfigMock;

    protected MockObject $didJwkResolverMock;

    protected MockObject $didDocumentFactoryMock;

    protected MockObject $didFactoryMock;

    protected MockObject $loggerServiceMock;

    protected StatusListContentHasher $statusListContentHasher;

    protected Helpers $helpers;

    /** The library's own facade in place of the double, for a test which signs for real. */
    protected ?TokenStatusList $tokenStatusList = null;


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

        $this->didDocumentFactoryMock = $this->createMock(DidDocumentFactory::class);
        $this->didDocumentFactoryMock->method('verificationMethodIdFor')->willReturnCallback(
            static fn(DidUrl $did, string $keyId): DidUrl => new DidUrl($did->getDid() . '#' . $keyId),
        );

        $this->didFactoryMock = $this->createMock(DidFactory::class);
        $this->didFactoryMock->method('didJwkResolver')->willReturn($this->didJwkResolverMock);
        $this->didFactoryMock->method('didDocumentFactory')->willReturn($this->didDocumentFactoryMock);
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
        $tokenStatusListMock = $this->createMock(TokenStatusList::class);
        $tokenStatusListMock->method('statusListFactory')
            ->willReturn(new StatusListFactory(new OpenIdHelpers()));
        $tokenStatusListMock->method('statusListTokenFactory')
            ->willReturn($this->statusListTokenFactoryMock);
        $tokenStatusListMock->method('helpers')->willReturn(new OpenIdHelpers());

        return new DbStatusListTokenProvider(
            $this->statusListRepositoryMock,
            $this->statusListEntryRepositoryMock,
            $this->statusListContentHasher,
            $this->statusListKeyResolverMock,
            $this->tokenStatusList ?? $tokenStatusListMock,
            $this->moduleConfigMock,
            $this->didFactoryMock,
            $this->helpers,
            $this->loggerServiceMock,
        );
    }


    /**
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    protected function signatureKeyPair(): SignatureKeyPair
    {
        $publicKey = (new JwkDecoratorFactory())->fromData(['kty' => 'EC', 'crv' => 'P-256', 'x' => 'x', 'y' => 'y']);

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
        ?string $issuerIdentifier = null,
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
            $issuerIdentifier,
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
     * Under the did:web profile the token names the identifier the list was created under, and the key
     * by the verification method the published DID document gives it.
     *
     * @throws \Exception
     */
    public function testSignsWithTheRecordedDidWebIdentity(): void
    {
        $this->givenAListWhichNeedsPublishing(StatusListKeyProfileEnum::DidWeb, self::DID_WEB);
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
                self::DID_WEB,
                [],
                ['kid' => self::DID_WEB . '#' . self::SIGNING_KEY_ID],
            )
            ->willReturn($this->signedTokenStub());

        $this->sut()->getToken(self::LIST_ID);
    }


    /**
     * The configured identity is never consulted, so changing or clearing it leaves every list already
     * being served naming the issuer its holders resolved it under.
     *
     * @throws \Exception
     */
    public function testTheConfiguredIssuerIdentityIsNeverReadWhenSigning(): void
    {
        $this->moduleConfigMock->expects($this->never())->method('getVciIssuerDidIdentifier');
        $this->moduleConfigMock->expects($this->never())->method('getVciIssuerIdentifier');
        $this->moduleConfigMock->expects($this->never())->method('getVciIssuerIdentifierMode');

        $this->givenAListWhichNeedsPublishing(StatusListKeyProfileEnum::DidWeb, self::DID_WEB);

        $this->sut()->getToken(self::LIST_ID);
    }


    /**
     * Both identities are minted from key material already in hand, so neither may depend on the facade
     * whose construction reads the cache adapter and the outbound destination settings -- neither of
     * which signing a list has any use for.
     *
     * @throws \Exception
     */
    public function testSigningNeverBuildsTheResolvingFacade(): void
    {
        $this->didFactoryMock->expects($this->never())->method('build');

        $this->givenAListWhichNeedsPublishing(StatusListKeyProfileEnum::DidWeb, self::DID_WEB);

        $this->sut()->getToken(self::LIST_ID);
    }


    /**
     * A key identifier which cannot be built is reported rather than worked around, since the only ways
     * around it would be to sign with a `kid` the published document does not carry or to sign with
     * none at all.
     *
     * @throws \Exception
     */
    public function testReportsAFailureToMintTheDidWebVerificationMethodId(): void
    {
        $didDocumentFactoryMock = $this->createMock(DidDocumentFactory::class);
        $didDocumentFactoryMock->method('verificationMethodIdFor')
            ->willThrowException(new RuntimeException('nope'));

        $this->didFactoryMock = $this->createMock(DidFactory::class);
        $this->didFactoryMock->method('didDocumentFactory')->willReturn($didDocumentFactoryMock);

        $this->givenAListWhichNeedsPublishing(StatusListKeyProfileEnum::DidWeb, self::DID_WEB);

        $this->expectException(StatusListException::class);
        $this->expectExceptionMessage('did:web');

        $this->sut()->getToken(self::LIST_ID);
    }


    /**
     * Signing under a guessed identity would be worse than not signing at all: the token would name an
     * issuer the list was never created under, and a wallet cannot tell the difference.
     *
     * @throws \Exception
     */
    public function testRefusesToSignADidWebListWhichRecordedNoIdentifier(): void
    {
        $this->givenAListWhichNeedsPublishing(StatusListKeyProfileEnum::DidWeb);

        $this->expectException(StatusListException::class);
        $this->expectExceptionMessage('no issuer identifier');

        $this->sut()->getToken(self::LIST_ID);
    }


    /**
     * Whatever signing throws is reported as one failure to sign this list, with the cause kept whole:
     * its message in the report, its code as the code, itself as the previous exception. Nothing is
     * published.
     *
     * @throws \Exception
     */
    public function testReportsAFailureToSign(): void
    {
        $cause = new RuntimeException('the private key is unusable', 17);

        $this->statusListTokenFactoryMock = $this->createMock(StatusListTokenFactory::class);
        $this->statusListTokenFactoryMock->method('forStatusList')->willThrowException($cause);

        $this->givenAListWhichNeedsPublishing();
        $this->statusListRepositoryMock->expects($this->never())->method('publishToken');

        try {
            $this->sut()->getToken(self::LIST_ID);
            $this->fail('No exception was raised.');
        } catch (StatusListException $exception) {
            $this->assertSame(
                'Unable to sign a Status List Token for "a-status-list-id": the private key is unusable',
                $exception->getMessage(),
            );
            $this->assertSame(17, $exception->getCode());
            $this->assertSame($cause, $exception->getPrevious());
        }
    }


    /**
     * Building the list from its entries is under the same report as signing it. An entry at an index the
     * list has no room for -- a damaged row, since the allocator draws indices below the capacity -- is
     * refused by the library, and the refusal is reported as a failure to sign this list, with the
     * library's own words and exception kept.
     *
     * @throws \Exception
     */
    public function testReportsAnEntryTheListHasNoRoomFor(): void
    {
        $this->givenAListWhichNeedsPublishing();
        $this->statusListEntryRepositoryMock = $this->createMock(StatusListEntryRepository::class);
        $this->statusListEntryRepositoryMock->method('findNonValidStatuses')->willReturn([64 => 1]);

        $this->statusListTokenFactoryMock->expects($this->never())->method('forStatusList');
        $this->statusListRepositoryMock->expects($this->never())->method('publishToken');

        try {
            $this->sut()->getToken(self::LIST_ID);
            $this->fail('No exception was raised.');
        } catch (StatusListException $exception) {
            $this->assertSame(
                'Unable to sign a Status List Token for "a-status-list-id": ' .
                'Index 64 is out of bounds of the Status List (capacity 64).',
                $exception->getMessage(),
            );
            // The library's refusal carries no code, so none is carried over.
            $this->assertSame(0, $exception->getCode());
            $this->assertInstanceOf(LibraryStatusListException::class, $exception->getPrevious());
        }
    }


    /**
     * The did:jwk identity is minted from the key before anything is signed, so a public key which
     * cannot be turned into one fails the request there, with the cause kept whole, nothing signed and
     * nothing published.
     *
     * @throws \Exception
     */
    public function testReportsAFailureToDeriveTheDidJwkIdentifier(): void
    {
        $cause = new RuntimeException('not a JWK', 3);

        $this->didJwkResolverMock = $this->createMock(DidJwkResolver::class);
        $this->didJwkResolverMock->method('generateDidJwkFromJwk')->willThrowException($cause);
        $this->didFactoryMock = $this->createMock(DidFactory::class);
        $this->didFactoryMock->method('didJwkResolver')->willReturn($this->didJwkResolverMock);

        $this->givenAListWhichNeedsPublishing();
        $this->statusListTokenFactoryMock->expects($this->never())->method('forStatusList');
        $this->statusListRepositoryMock->expects($this->never())->method('publishToken');

        try {
            $this->sut()->getToken(self::LIST_ID);
            $this->fail('No exception was raised.');
        } catch (StatusListException $exception) {
            $this->assertSame(
                'Unable to derive the did:jwk identifier for the Status List signing key: not a JWK',
                $exception->getMessage(),
            );
            $this->assertSame(3, $exception->getCode());
            $this->assertSame($cause, $exception->getPrevious());
        }
    }


    /**
     * @throws \Exception
     */
    protected function givenAListWhichNeedsPublishing(
        StatusListKeyProfileEnum $keyProfile = StatusListKeyProfileEnum::DidJwk,
        ?string $issuerIdentifier = null,
    ): void {
        $record = $this->record(keyProfile: $keyProfile, issuerIdentifier: $issuerIdentifier);

        $this->statusListRepositoryMock->method('findById')->willReturn($record);
        $this->statusListRepositoryMock->method('findByIdOnPrimary')->willReturn($record);
        $this->statusListEntryRepositoryMock->method('findNonValidStatuses')->willReturn([]);
        $this->statusListRepositoryMock->method('publishToken')->willReturn(true);
    }


    /**
     * A certificate chain whose `x5c` is the given one, valid until the given moment.
     *
     * @param non-empty-list<non-empty-string> $x5c
     */
    protected function certificateChain(array $x5c, int $earliestNotAfter): VciCertificateChain
    {
        $certificateChainMock = $this->createMock(VciCertificateChain::class);
        $certificateChainMock->method('getX5c')->willReturn($x5c);
        $certificateChainMock->method('getEarliestNotAfter')->willReturn($earliestNotAfter);

        return $certificateChainMock;
    }


    /**
     * A list under the `x509` key profile with the given token published just now, with its full life ahead of it.
     *
     * @throws \Exception
     */
    protected function publishedX509Record(
        string $token,
        string $expiresAt = '+7 days',
        string $issuedAt = 'now',
    ): StatusListRecord {
        return $this->record(
            $token,
            $this->contentHashFor([]),
            $issuedAt,
            $expiresAt,
            keyProfile: StatusListKeyProfileEnum::X509,
        );
    }


    /**
     * A token as this provider publishes it under the `x509` key profile: what is read of it is its header.
     *
     * @param list<string> $x5c
     */
    protected function tokenCarrying(array $x5c): string
    {
        $base64Url = (new OpenIdHelpers())->base64Url();

        $header = $base64Url->encode((string)json_encode(['alg' => 'ES256', 'typ' => 'statuslist+jwt', 'x5c' => $x5c]));

        return $header . '.' . $base64Url->encode('{}') . '.c2lnbmF0dXJl';
    }


    /**
     * Under the `x509` key profile the token names the issuer by its URL and the key by its certificate chain,
     * without the trust anchor and without a `kid` (HAIP 1.0 section 6.1). The chain is that of the key the list was
     * created with, which is the one it is signed with.
     *
     * @throws \Exception
     */
    public function testSignsWithTheIssuerAndTheCertificateChainUnderTheX509Profile(): void
    {
        $this->givenAListWhichNeedsPublishing(StatusListKeyProfileEnum::X509);
        $signatureKeyPair = $this->signatureKeyPair();
        $this->statusListKeyResolverMock = $this->createMock(StatusListKeyResolver::class);
        $this->statusListKeyResolverMock->method('getByKeyId')->with(self::SIGNING_KEY_ID)
            ->willReturn($signatureKeyPair);
        $this->statusListKeyResolverMock->expects($this->atLeastOnce())->method('getCertificateChainFor')
            ->with($signatureKeyPair)
            ->willReturn($this->certificateChain(['bGVhZg==', 'aW50ZXJtZWRpYXRl'], time() + 86400 * 365));
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
                ['x5c' => ['bGVhZg==', 'aW50ZXJtZWRpYXRl']],
            )
            ->willReturn($this->signedTokenStub());

        $this->sut()->getToken(self::LIST_ID);
    }


    /**
     * A token under the `x509` key profile names its key by nothing but the chain, so a key without a usable one
     * does not sign one at all.
     *
     * @throws \Exception
     */
    public function testDoesNotSignAnX509ListWhoseKeyHasNoUsableChain(): void
    {
        $this->givenAListWhichNeedsPublishing(StatusListKeyProfileEnum::X509);
        $this->statusListKeyResolverMock->method('getCertificateChainFor')
            ->willThrowException(new StatusListException('The key "vci-signing-key" has no certificate chain.'));
        $this->statusListTokenFactoryMock->expects($this->never())->method('forStatusList');
        $this->statusListRepositoryMock->expects($this->never())->method('publishToken');

        $this->expectException(StatusListException::class);
        $this->expectExceptionMessage('The key "vci-signing-key" has no certificate chain.');

        $this->sut()->getToken(self::LIST_ID);
    }


    /**
     * A token never outlives a certificate it carries: when the chain expires before the list's token validity is
     * up (an intermediate, say), the token expires with it, and its `ttl` stops there too. So does what it is
     * published with, which StatusListTokenResult serves the cache lifetime from.
     *
     * @throws \Exception
     */
    public function testAnX509TokenExpiresNoLaterThanItsCertificateChain(): void
    {
        $chainExpiresAt = time() + 7200;
        $this->givenAListWhichNeedsPublishing(StatusListKeyProfileEnum::X509);
        $this->statusListKeyResolverMock->method('getCertificateChainFor')
            ->willReturn($this->certificateChain(['bGVhZg=='], $chainExpiresAt));
        $this->loggerServiceMock->expects($this->once())->method('warning')
            ->with($this->stringContains('expires early because a certificate of its key\'s chain does'));

        $signed = [];
        $this->statusListTokenFactoryMock = $this->createMock(StatusListTokenFactory::class);
        $this->statusListTokenFactoryMock->method('forStatusList')->willReturnCallback(
            function (mixed ...$arguments) use (&$signed): StatusListToken {
                $signed = $arguments;

                return $this->signedTokenStub();
            },
        );

        $result = $this->sut()->getToken(self::LIST_ID);

        $this->assertInstanceOf(StatusListTokenResult::class, $result);
        $this->assertSame($chainExpiresAt, $result->getExpiresAt()->getTimestamp());
        [, , , , $issuedAt, $expiresAt, $ttl] = $signed;
        $this->assertInstanceOf(DateTimeImmutable::class, $issuedAt);
        $this->assertInstanceOf(DateTimeImmutable::class, $expiresAt);
        $this->assertInstanceOf(DateInterval::class, $ttl);
        $this->assertSame($chainExpiresAt, $expiresAt->getTimestamp());
        $this->assertSame(
            $chainExpiresAt - $issuedAt->getTimestamp(),
            (new DateTimeImmutable('@0'))->add($ttl)->getTimestamp(),
        );
        $this->assertLessThanOrEqual(7200, $result->getMaxAgeSeconds($issuedAt));
    }


    /**
     * A chain which outlives the token's validity leaves both as the list has them.
     *
     * @throws \Exception
     */
    public function testAnX509TokenKeepsItsValidityWhenItsCertificateChainOutlivesIt(): void
    {
        $this->givenAListWhichNeedsPublishing(StatusListKeyProfileEnum::X509);
        $this->statusListKeyResolverMock->method('getCertificateChainFor')
            ->willReturn($this->certificateChain(['bGVhZg=='], time() + 86400 * 30));
        $this->loggerServiceMock->expects($this->never())->method('warning');

        $signed = [];
        $this->statusListTokenFactoryMock = $this->createMock(StatusListTokenFactory::class);
        $this->statusListTokenFactoryMock->method('forStatusList')->willReturnCallback(
            function (mixed ...$arguments) use (&$signed): StatusListToken {
                $signed = $arguments;

                return $this->signedTokenStub();
            },
        );

        $this->sut()->getToken(self::LIST_ID);

        [, , , , $issuedAt, $expiresAt, $ttl] = $signed;
        $this->assertInstanceOf(DateTimeImmutable::class, $issuedAt);
        $this->assertInstanceOf(DateTimeImmutable::class, $expiresAt);
        $this->assertInstanceOf(DateInterval::class, $ttl);
        $this->assertSame(604800, $expiresAt->getTimestamp() - $issuedAt->getTimestamp());
        $this->assertSame(43200, (new DateTimeImmutable('@0'))->add($ttl)->getTimestamp());
    }


    /**
     * A published token carrying the chain its key has now is served as it is.
     *
     * @throws \Exception
     */
    public function testServesAnX509TokenWhichCarriesTheCurrentCertificateChain(): void
    {
        $token = $this->tokenCarrying(['bGVhZg==', 'aW50ZXJtZWRpYXRl']);
        $this->statusListRepositoryMock->method('findById')->willReturn($this->publishedX509Record($token));
        $this->statusListKeyResolverMock->method('getCertificateChainFor')
            ->willReturn($this->certificateChain(['bGVhZg==', 'aW50ZXJtZWRpYXRl'], time() + 86400 * 30));
        $this->statusListRepositoryMock->expects($this->never())->method('publishToken');

        $result = $this->sut()->getToken(self::LIST_ID);

        $this->assertInstanceOf(StatusListTokenResult::class, $result);
        $this->assertSame($token, $result->getToken());
    }


    /**
     * A renewed certificate, the same key included, retires the published token signed under the old chain: the
     * list is signed again with the chain the key has now.
     *
     * @throws \Exception
     */
    public function testRepublishesAnX509TokenWhoseCertificateChainWasReplaced(): void
    {
        $record = $this->publishedX509Record(
            $this->tokenCarrying(['b2xkIGxlYWY=', 'aW50ZXJtZWRpYXRl']),
            issuedAt: '-10 minutes',
        );
        $this->statusListRepositoryMock->method('findById')->willReturn($record);
        $this->statusListRepositoryMock->method('findByIdOnPrimary')->willReturn($record);
        $this->statusListEntryRepositoryMock->method('findNonValidStatuses')->willReturn([]);
        $this->statusListKeyResolverMock->method('getCertificateChainFor')
            ->willReturn($this->certificateChain(['bmV3IGxlYWY=', 'aW50ZXJtZWRpYXRl'], time() + 86400 * 30));
        $this->statusListRepositoryMock->expects($this->once())->method('publishToken')->willReturn(true);

        $result = $this->sut()->getToken(self::LIST_ID);

        $this->assertInstanceOf(StatusListTokenResult::class, $result);
        $this->assertSame(self::SIGNED_TOKEN, $result->getToken());
    }


    /**
     * Content which has not changed is published again only with a later `iat` than the published token's, so a
     * renewed certificate within the second that token was issued in does not replace it then: it is served, rather
     * than three signings failing to publish.
     *
     * @throws \Exception
     */
    public function testServesAnX509TokenWhichCanNotBeReplacedWithinTheSecondItWasIssuedIn(): void
    {
        $token = $this->tokenCarrying(['b2xkIGxlYWY=', 'aW50ZXJtZWRpYXRl']);
        $record = $this->publishedX509Record($token, issuedAt: '+1 second');
        $this->statusListRepositoryMock->method('findById')->willReturn($record);
        $this->statusListRepositoryMock->method('findByIdOnPrimary')->willReturn($record);
        $this->statusListEntryRepositoryMock->method('findNonValidStatuses')->willReturn([]);
        $this->statusListKeyResolverMock->method('getCertificateChainFor')
            ->willReturn($this->certificateChain(['bmV3IGxlYWY=', 'aW50ZXJtZWRpYXRl'], time() + 86400 * 30));
        $this->statusListTokenFactoryMock->expects($this->never())->method('forStatusList');
        $this->statusListRepositoryMock->expects($this->never())->method('publishToken');

        $result = $this->sut()->getToken(self::LIST_ID);

        $this->assertInstanceOf(StatusListTokenResult::class, $result);
        $this->assertSame($token, $result->getToken());
    }


    /**
     * Whether the published token is still unexpired is asked of the clock after the status query, not before it:
     * an expired token is never served for being unreplaceable.
     *
     * @throws \Exception
     */
    public function testDoesNotServeAnUnreplaceableTokenWhichExpiredDuringTheStatusQuery(): void
    {
        $start = time();
        $queried = false;
        $dateTimeMock = $this->createMock(DateTimeHelper::class);
        $dateTimeMock->method('getUtc')->willReturnCallback(
            static function () use (&$queried, $start): DateTimeImmutable {
                return new DateTimeImmutable('@' . ($queried ? $start + 10 : $start));
            },
        );
        $helpersMock = $this->createMock(Helpers::class);
        $helpersMock->method('dateTime')->willReturn($dateTimeMock);
        $this->helpers = $helpersMock;

        $record = $this->publishedX509Record(
            $this->tokenCarrying(['b2xkIGxlYWY=']),
            '@' . ($start + 5),
            '@' . $start,
        );
        $this->statusListRepositoryMock->method('findById')->willReturn($record);
        $this->statusListRepositoryMock->method('findByIdOnPrimary')->willReturn($record);
        $this->statusListEntryRepositoryMock = $this->createMock(StatusListEntryRepository::class);
        $this->statusListEntryRepositoryMock->method('findNonValidStatuses')->willReturnCallback(
            static function () use (&$queried): array {
                $queried = true;

                return [];
            },
        );
        $this->statusListKeyResolverMock->method('getCertificateChainFor')
            ->willReturn($this->certificateChain(['bmV3IGxlYWY='], $start + 86400 * 30));
        $this->statusListRepositoryMock->method('publishToken')->willReturn(true);

        $result = $this->sut()->getToken(self::LIST_ID);

        $this->assertInstanceOf(StatusListTokenResult::class, $result);
        $this->assertSame(self::SIGNED_TOKEN, $result->getToken());
    }


    /**
     * Whether the published token is still unexpired is asked again after its chain is resolved, which reads files
     * and validates a path: a token which expired meanwhile is not served, though the chain can not be resolved.
     *
     * @throws \Exception
     */
    public function testDoesNotServeAnX509TokenWhichExpiredWhileItsChainWasResolved(): void
    {
        $start = time();
        $resolved = false;
        $dateTimeMock = $this->createMock(DateTimeHelper::class);
        $dateTimeMock->method('getUtc')->willReturnCallback(
            static function () use (&$resolved, $start): DateTimeImmutable {
                return new DateTimeImmutable('@' . ($resolved ? $start + 10 : $start));
            },
        );
        $helpersMock = $this->createMock(Helpers::class);
        $helpersMock->method('dateTime')->willReturn($dateTimeMock);
        $this->helpers = $helpersMock;

        $record = $this->publishedX509Record(
            $this->tokenCarrying(['bGVhZg==']),
            '@' . ($start + 5),
            '@' . ($start - 600),
        );
        $this->statusListRepositoryMock->method('findById')->willReturn($record);
        $this->statusListRepositoryMock->method('findByIdOnPrimary')->willReturn($record);
        $this->statusListEntryRepositoryMock->method('findNonValidStatuses')->willReturn([]);
        $this->statusListKeyResolverMock->method('getCertificateChainFor')->willReturnCallback(
            static function () use (&$resolved): never {
                $resolved = true;

                throw new StatusListException('The certificate chain has expired.');
            },
        );
        $this->statusListRepositoryMock->expects($this->never())->method('publishToken');

        $this->expectException(StatusListException::class);
        $this->expectExceptionMessage('The certificate chain has expired.');

        $this->sut()->getToken(self::LIST_ID);
    }


    /**
     * An expired token is refused before its chain is resolved, so a chain which can not be resolved is reported by
     * the signing which then fails, not as a token being served.
     *
     * @throws \Exception
     */
    public function testRefusesAnExpiredX509TokenBeforeResolvingItsChain(): void
    {
        $record = $this->publishedX509Record($this->tokenCarrying(['bGVhZg==']), '-1 minute', '-10 minutes');
        $this->statusListRepositoryMock->method('findById')->willReturn($record);
        $this->statusListRepositoryMock->method('findByIdOnPrimary')->willReturn($record);
        $this->statusListEntryRepositoryMock->method('findNonValidStatuses')->willReturn([]);
        $this->statusListKeyResolverMock->method('getCertificateChainFor')
            ->willThrowException(new StatusListException('The certificate chain has expired.'));
        $this->loggerServiceMock->expects($this->never())->method('error');
        $this->statusListRepositoryMock->expects($this->never())->method('publishToken');

        $this->expectException(StatusListException::class);
        $this->expectExceptionMessage('The certificate chain has expired.');

        $this->sut()->getToken(self::LIST_ID);
    }


    /**
     * Nor does the safety margin, then: a replacement could not be signed.
     *
     * @throws \Exception
     */
    public function testServesAnX509TokenCloseToItsExpiryWhileItsKeysCertificateChainCanNotBeResolved(): void
    {
        $token = $this->tokenCarrying(['bGVhZg==']);
        $this->statusListRepositoryMock->method('findById')
            ->willReturn($this->publishedX509Record($token, '+5 minutes', '-10 minutes'));
        $this->statusListKeyResolverMock->method('getCertificateChainFor')
            ->willThrowException(new StatusListException('The certificate chain can not be read.'));
        $this->statusListRepositoryMock->expects($this->never())->method('publishToken');

        $result = $this->sut()->getToken(self::LIST_ID);

        $this->assertInstanceOf(StatusListTokenResult::class, $result);
        $this->assertSame($token, $result->getToken());
    }


    /**
     * The chain is asked whether it has expired by the clock when the token is signed, not when its list was read:
     * the status query in between can take long enough for it to have expired.
     *
     * @throws \Exception
     */
    public function testDoesNotSignAnX509ListWhoseCertificateChainExpiredDuringTheStatusQuery(): void
    {
        $start = time();
        $queried = false;
        $dateTimeMock = $this->createMock(DateTimeHelper::class);
        $dateTimeMock->method('getUtc')->willReturnCallback(
            static function () use (&$queried, $start): DateTimeImmutable {
                return new DateTimeImmutable('@' . ($queried ? $start + 120 : $start));
            },
        );
        $helpersMock = $this->createMock(Helpers::class);
        $helpersMock->method('dateTime')->willReturn($dateTimeMock);
        $this->helpers = $helpersMock;

        $this->givenAListWhichNeedsPublishing(StatusListKeyProfileEnum::X509);
        $this->statusListEntryRepositoryMock = $this->createMock(StatusListEntryRepository::class);
        $this->statusListEntryRepositoryMock->method('findNonValidStatuses')->willReturnCallback(
            static function () use (&$queried): array {
                $queried = true;

                return [];
            },
        );
        $this->statusListKeyResolverMock->method('getCertificateChainFor')
            ->willReturn($this->certificateChain(['bGVhZg=='], $start + 60));
        $this->statusListTokenFactoryMock->expects($this->never())->method('forStatusList');

        $this->expectException(StatusListException::class);
        $this->expectExceptionMessage('has expired');

        $this->sut()->getToken(self::LIST_ID);
    }


    /**
     * A chain which can not be resolved now does not take the list's status offline while its published token,
     * signed under a chain validated then, still holds: the token is served, and the fault logged for the operator,
     * as signing will fail when the token is due to be replaced.
     *
     * @throws \Exception
     */
    public function testServesAnX509TokenWhileItsKeysCertificateChainCanNotBeResolved(): void
    {
        $token = $this->tokenCarrying(['bGVhZg==']);
        $this->statusListRepositoryMock->method('findById')->willReturn($this->publishedX509Record($token));
        $this->statusListKeyResolverMock->method('getCertificateChainFor')
            ->willThrowException(new StatusListException('The certificate chain has expired.'));
        $this->loggerServiceMock->expects($this->once())->method('error')
            ->with($this->stringContains('The certificate chain has expired.'));
        $this->statusListRepositoryMock->expects($this->never())->method('publishToken');

        $result = $this->sut()->getToken(self::LIST_ID);

        $this->assertInstanceOf(StatusListTokenResult::class, $result);
        $this->assertSame($token, $result->getToken());
    }


    /**
     * A token which expires with its certificate chain is served to its expiry: one signed now could not last
     * longer, and replacing it within the safety margin would sign one per request, which two requests in one second
     * could not both publish.
     *
     * @throws \Exception
     */
    public function testServesAnX509TokenWhichExpiresWithItsCertificateChainToItsExpiry(): void
    {
        $expiresAt = time() + 300;
        $token = $this->tokenCarrying(['bGVhZg==']);
        $this->statusListRepositoryMock->method('findById')
            ->willReturn($this->publishedX509Record($token, '@' . $expiresAt));
        $this->statusListKeyResolverMock->method('getCertificateChainFor')
            ->willReturn($this->certificateChain(['bGVhZg=='], $expiresAt));
        $this->statusListRepositoryMock->expects($this->never())->method('publishToken');

        $result = $this->sut()->getToken(self::LIST_ID);

        $this->assertInstanceOf(StatusListTokenResult::class, $result);
        $this->assertSame($token, $result->getToken());
    }


    /**
     * A token close to its expiry is replaced as any other is when its chain would let a new one last longer.
     *
     * @throws \Exception
     */
    public function testReplacesAnX509TokenCloseToItsExpiryWhenItsCertificateChainOutlivesIt(): void
    {
        $record = $this->publishedX509Record($this->tokenCarrying(['bGVhZg==']), '+5 minutes', '-10 minutes');
        $this->statusListRepositoryMock->method('findById')->willReturn($record);
        $this->statusListRepositoryMock->method('findByIdOnPrimary')->willReturn($record);
        $this->statusListEntryRepositoryMock->method('findNonValidStatuses')->willReturn([]);
        $this->statusListKeyResolverMock->method('getCertificateChainFor')
            ->willReturn($this->certificateChain(['bGVhZg=='], time() + 86400 * 30));
        $this->statusListRepositoryMock->expects($this->once())->method('publishToken')->willReturn(true);

        $result = $this->sut()->getToken(self::LIST_ID);

        $this->assertInstanceOf(StatusListTokenResult::class, $result);
        $this->assertSame(self::SIGNED_TOKEN, $result->getToken());
    }


    /**
     * An expired token is never served, though it expired with the chain it carries: once the key's certificate has
     * been renewed, with the chain it carries, the list is signed again.
     *
     * @throws \Exception
     */
    public function testDoesNotServeAnExpiredX509Token(): void
    {
        $record = $this->publishedX509Record($this->tokenCarrying(['bGVhZg==']), '@' . (time() - 60));
        $this->statusListRepositoryMock->method('findById')->willReturn($record);
        $this->statusListRepositoryMock->method('findByIdOnPrimary')->willReturn($record);
        $this->statusListEntryRepositoryMock->method('findNonValidStatuses')->willReturn([]);
        $this->statusListKeyResolverMock->method('getCertificateChainFor')
            ->willReturn($this->certificateChain(['bGVhZg=='], time() + 86400 * 30));
        $this->statusListRepositoryMock->expects($this->once())->method('publishToken')->willReturn(true);

        $result = $this->sut()->getToken(self::LIST_ID);

        $this->assertInstanceOf(StatusListTokenResult::class, $result);
        $this->assertSame(self::SIGNED_TOKEN, $result->getToken());
    }


    /**
     * A chain which expired after it was resolved, earlier in the request, signs nothing: the token would be expired
     * already.
     *
     * @throws \Exception
     */
    public function testDoesNotSignAnX509ListWhoseCertificateChainHasExpired(): void
    {
        $this->givenAListWhichNeedsPublishing(StatusListKeyProfileEnum::X509);
        $this->statusListKeyResolverMock->method('getCertificateChainFor')
            ->willReturn($this->certificateChain(['bGVhZg=='], time() - 1));
        $this->statusListTokenFactoryMock->expects($this->never())->method('forStatusList');
        $this->statusListRepositoryMock->expects($this->never())->method('publishToken');

        $this->expectException(StatusListException::class);
        $this->expectExceptionMessage('The certificate chain of the key of Status List "a-status-list-id" has expired');

        $this->sut()->getToken(self::LIST_ID);
    }


    /**
     * A key which can not be loaded any more is the same fault as a chain which can not be used: the published token
     * is served while it holds.
     *
     * @throws \Exception
     */
    public function testServesAnX509TokenWhileItsKeyCanNotBeLoaded(): void
    {
        $token = $this->tokenCarrying(['bGVhZg==']);
        $this->statusListRepositoryMock->method('findById')->willReturn($this->publishedX509Record($token));
        $this->statusListKeyResolverMock = $this->createMock(StatusListKeyResolver::class);
        $this->statusListKeyResolverMock->method('getByKeyId')
            ->willThrowException(new RuntimeException('The private key file can not be read.'));
        $this->loggerServiceMock->expects($this->once())->method('error')
            ->with($this->stringContains('The private key file can not be read.'));
        $this->statusListRepositoryMock->expects($this->never())->method('publishToken');

        $result = $this->sut()->getToken(self::LIST_ID);

        $this->assertInstanceOf(StatusListTokenResult::class, $result);
        $this->assertSame($token, $result->getToken());
    }


    /**
     * What a HAIP Relying Party does with a Status List Token: validate its `x5c` chain against the trust anchor,
     * and verify the signature with the leaf's key (HAIP 1.0 section 6.1). Signed for real.
     *
     * @throws \Exception
     */
    public function testAnX509TokenVerifiesThroughItsCertificateChain(): void
    {
        $rootKey = CertificateBuilder::ecKey();
        $intermediateKey = CertificateBuilder::ecKey();
        $leafKey = CertificateBuilder::ecKey();
        $root = CertificateBuilder::root($rootKey);
        $intermediate = CertificateBuilder::certificate(
            'CN=Test Intermediate CA',
            $intermediateKey,
            'CN=Test Root CA',
            $rootKey,
            CertificateBuilder::caExtensions(),
        );
        $leaf = CertificateBuilder::certificate(
            'CN=Test Credential Issuer',
            $leafKey,
            'CN=Test Intermediate CA',
            $intermediateKey,
            CertificateBuilder::leafExtensions(['https://op.example.org']),
        );
        $x509 = new X509();
        $trustAnchors = [$x509->certificateFactory()->fromDer($root)];
        $chain = $x509->certificateFactory()->chainFromPem(CertificateBuilder::pem($leaf, $intermediate));

        $keyPair = $this->createMock(KeyPair::class);
        $keyPair->method('getKeyId')->willReturn(self::SIGNING_KEY_ID);
        $keyPair->method('getPrivateKey')->willReturn(
            (new JwkDecoratorFactory())->fromPkcs1Or8Key(CertificateBuilder::privateKeyPem($leafKey)),
        );
        $signatureKeyPair = $this->createMock(SignatureKeyPair::class);
        $signatureKeyPair->method('getKeyPair')->willReturn($keyPair);
        $signatureKeyPair->method('getSignatureAlgorithm')->willReturn(SignatureAlgorithmEnum::ES256);
        $this->statusListKeyResolverMock = $this->createMock(StatusListKeyResolver::class);
        $this->statusListKeyResolverMock->method('getByKeyId')->willReturn($signatureKeyPair);
        $this->statusListKeyResolverMock->method('getCertificateChainFor')->willReturn(
            new VciCertificateChain($chain, $x509->certificatePathValidator()->validate($chain, $trustAnchors)),
        );
        $this->tokenStatusList = new TokenStatusList(
            new SupportedAlgorithms(new SignatureAlgorithmBag(SignatureAlgorithmEnum::ES256)),
        );
        $this->givenAListWhichNeedsPublishing(StatusListKeyProfileEnum::X509);

        $result = $this->sut()->getToken(self::LIST_ID);

        $this->assertInstanceOf(StatusListTokenResult::class, $result);
        $token = $this->tokenStatusList->statusListTokenFactory()->fromToken($result->getToken());
        $x5c = $token->getX509CertificateChain();
        $this->assertSame([base64_encode($leaf), base64_encode($intermediate)], $x5c);
        $this->assertArrayNotHasKey('kid', $token->getHeader());
        $this->assertSame('https://op.example.org', $token->getIssuer());

        $token->verifyWithX509CertificatePath(
            $x509->certificatePathValidator()->validate($x509->certificateFactory()->chainFromX5c($x5c), $trustAnchors),
        );
    }
}
