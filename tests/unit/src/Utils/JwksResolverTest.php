<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Utils;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Utils\JwksResolver;
use SimpleSAML\OpenID\Exceptions\JwsException;
use SimpleSAML\OpenID\Jwks;
use SimpleSAML\OpenID\Jwks\JwksDecorator;
use SimpleSAML\OpenID\Jwks\JwksFetcher;

/**
 * Where a client's keys come from, in order of preference: its signed JWKS, fetched from `signed_jwks_uri`
 * and verified with its federation JWKS, when it has both; its `jwks_uri`, fetched, when it has one; its
 * static `jwks` otherwise. The fetches go through the library's fetcher, cache first.
 *
 * The order is a precedence, not a fallback chain: a client with a `signed_jwks_uri` and federation keys
 * whose signed JWKS cannot be had gets no keys, not its `jwks_uri` or static set, and a client whose
 * `jwks_uri` cannot be had gets none either. Pinned as it stands; the three callers treat null as "no
 * keys": the request object rule and the client authentication resolver refuse, and the client rule gives
 * up resolving the federated client. A missing member of the signed pair, an empty string or an empty
 * array included, sends the client down to the next source.
 */
#[CoversClass(JwksResolver::class)]
#[AllowMockObjectsWithoutExpectations]
class JwksResolverTest extends TestCase
{
    protected const string SIGNED_JWKS_URI = 'https://rp.example.org/signed-jwks';

    protected const string JWKS_URI = 'https://rp.example.org/jwks';

    protected const array FEDERATION_JWKS = ['keys' => [['kty' => 'EC', 'kid' => 'federation-key']]];

    protected const array FETCHED_JWKS = ['keys' => [['kty' => 'EC', 'kid' => 'fetched-key']]];

    protected const array STATIC_JWKS = ['keys' => [['kty' => 'RSA', 'kid' => 'static-key']]];


    protected MockObject $jwksFetcherMock;

    protected MockObject $clientMock;


    protected function setUp(): void
    {
        $this->jwksFetcherMock = $this->createMock(JwksFetcher::class);
        $this->clientMock = $this->createMock(ClientEntityInterface::class);
    }


    protected function sut(): JwksResolver
    {
        $jwks = $this->createMock(Jwks::class);
        $jwks->method('jwksFetcher')->willReturn($this->jwksFetcherMock);

        return new JwksResolver($jwks);
    }


    protected function fetched(): JwksDecorator
    {
        $jwksDecorator = $this->createMock(JwksDecorator::class);
        $jwksDecorator->method('jsonSerialize')->willReturn(self::FETCHED_JWKS);

        return $jwksDecorator;
    }


    /**
     * @param ?array<string,mixed> $federationJwks
     * @param ?array<string,mixed> $jwks
     */
    protected function client(
        ?string $signedJwksUri = null,
        ?array $federationJwks = null,
        ?string $jwksUri = null,
        ?array $jwks = null,
    ): ClientEntityInterface {
        $this->clientMock->method('getSignedJwksUri')->willReturn($signedJwksUri);
        $this->clientMock->method('getFederationJwks')->willReturn($federationJwks);
        $this->clientMock->method('getJwksUri')->willReturn($jwksUri);
        $this->clientMock->method('getJwks')->willReturn($jwks);

        return $this->clientMock;
    }


    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(JwksResolver::class, $this->sut());
    }


    /**
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     */
    public function testPrefersTheSignedJwksVerifiedWithTheFederationKeys(): void
    {
        $this->jwksFetcherMock->expects($this->once())
            ->method('fromCacheOrSignedJwksUri')
            ->with(self::SIGNED_JWKS_URI, self::FEDERATION_JWKS)
            ->willReturn($this->fetched());
        $this->jwksFetcherMock->expects($this->never())->method('fromCacheOrJwksUri');
        $this->clientMock->expects($this->never())->method('getJwks');

        $jwks = $this->sut()->forClient(
            $this->client(self::SIGNED_JWKS_URI, self::FEDERATION_JWKS, self::JWKS_URI, self::STATIC_JWKS),
        );

        $this->assertSame(self::FETCHED_JWKS, $jwks);
    }


    /**
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     */
    public function testASignedJwksWhichCannotBeHadIsNoKeysAtAll(): void
    {
        $this->jwksFetcherMock->method('fromCacheOrSignedJwksUri')->willReturn(null);
        $this->jwksFetcherMock->expects($this->never())->method('fromCacheOrJwksUri');
        $this->clientMock->expects($this->never())->method('getJwks');

        $jwks = $this->sut()->forClient(
            $this->client(self::SIGNED_JWKS_URI, self::FEDERATION_JWKS, self::JWKS_URI, self::STATIC_JWKS),
        );

        $this->assertNull($jwks);
    }


    /**
     * @param ?array<string,mixed> $federationJwks
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     */
    #[DataProvider('incompleteSignedPairProvider')]
    public function testFetchesTheJwksUriWithoutBothMembersOfTheSignedPair(
        ?string $signedJwksUri,
        ?array $federationJwks,
    ): void {
        $this->jwksFetcherMock->expects($this->never())->method('fromCacheOrSignedJwksUri');
        $this->jwksFetcherMock->expects($this->once())
            ->method('fromCacheOrJwksUri')
            ->with(self::JWKS_URI)
            ->willReturn($this->fetched());
        $this->clientMock->expects($this->never())->method('getJwks');

        $jwks = $this->sut()->forClient(
            $this->client($signedJwksUri, $federationJwks, self::JWKS_URI, self::STATIC_JWKS),
        );

        $this->assertSame(self::FETCHED_JWKS, $jwks);
    }


    /**
     * @return array<string,array{?string,?array<string,mixed>}>
     */
    public static function incompleteSignedPairProvider(): array
    {
        return [
            'no signed_jwks_uri' => [null, self::FEDERATION_JWKS],
            'an empty signed_jwks_uri' => ['', self::FEDERATION_JWKS],
            'no federation keys' => [self::SIGNED_JWKS_URI, null],
            'an empty federation key set' => [self::SIGNED_JWKS_URI, []],
        ];
    }


    /**
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     */
    public function testAJwksUriWhichCannotBeHadIsNoKeysAtAll(): void
    {
        $this->jwksFetcherMock->method('fromCacheOrJwksUri')->willReturn(null);
        $this->clientMock->expects($this->never())->method('getJwks');

        $this->assertNull($this->sut()->forClient($this->client(jwksUri: self::JWKS_URI, jwks: self::STATIC_JWKS)));
    }


    /**
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     */
    #[DataProvider('noJwksUriProvider')]
    public function testFallsBackToTheStaticJwksWithoutAJwksUri(?string $jwksUri): void
    {
        $this->jwksFetcherMock->expects($this->never())->method($this->anything());

        $this->assertSame(
            self::STATIC_JWKS,
            $this->sut()->forClient($this->client(jwksUri: $jwksUri, jwks: self::STATIC_JWKS)),
        );
    }


    /**
     * @return array<string,array{?string}>
     */
    public static function noJwksUriProvider(): array
    {
        return [
            'no jwks_uri' => [null],
            'an empty jwks_uri' => [''],
        ];
    }


    /**
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     */
    public function testAClientWithNoKeySourceHasNoKeys(): void
    {
        $this->jwksFetcherMock->expects($this->never())->method($this->anything());

        $this->assertNull($this->sut()->forClient($this->client()));
    }


    /**
     * A signed JWKS which does not verify is the library's refusal, and it comes out as it is.
     *
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     */
    public function testLetsTheFetchersRefusalThrough(): void
    {
        $refusal = new JwsException('Signed JWKS signature verification failed.');
        $this->jwksFetcherMock->method('fromCacheOrSignedJwksUri')->willThrowException($refusal);

        $this->expectExceptionObject($refusal);

        $this->sut()->forClient($this->client(self::SIGNED_JWKS_URI, self::FEDERATION_JWKS));
    }
}
