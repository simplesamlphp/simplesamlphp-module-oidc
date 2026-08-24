<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers;

use DateInterval;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Controllers\StatusListController;
use SimpleSAML\Module\oidc\Exceptions\StatusListException;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\StatusList\Contracts\StatusListTokenProviderInterface;
use SimpleSAML\Module\oidc\StatusList\StatusListRateLimiter;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListTokenResult;
use SimpleSAML\Module\oidc\Utils\HttpContentNegotiator;
use SimpleSAML\Module\oidc\Utils\Routes;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

#[CoversClass(StatusListController::class)]
#[AllowMockObjectsWithoutExpectations]
class StatusListControllerTest extends TestCase
{
    protected const string LIST_ID = 'a-status-list-id';

    protected const string TOKEN = 'header.payload.signature';


    protected MockObject $statusListTokenProviderMock;

    protected MockObject $statusListRateLimiterMock;

    protected MockObject $routesMock;

    protected MockObject $loggerServiceMock;

    protected Helpers $helpers;


    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->statusListTokenProviderMock = $this->createMock(StatusListTokenProviderInterface::class);
        $this->statusListRateLimiterMock = $this->createMock(StatusListRateLimiter::class);
        $this->statusListRateLimiterMock->method('allows')->willReturn(true);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        $this->helpers = new Helpers();

        $this->routesMock = $this->createMock(Routes::class);
        $this->routesMock->method('newResponse')->willReturnCallback(
            static fn(?string $content = '', int $status = 200, array $headers = []): Response =>
                new Response($content, $status, $headers),
        );

        $this->statusListTokenProviderMock->method('getToken')->willReturn($this->tokenResult());
    }


    /**
     * @throws \Exception
     */
    protected function tokenResult(): StatusListTokenResult
    {
        $issuedAt = $this->helpers->dateTime()->getUtc();

        return new StatusListTokenResult(
            self::TOKEN,
            43200,
            $issuedAt,
            $issuedAt->add(new DateInterval('P7D')),
        );
    }


    protected function sut(): StatusListController
    {
        return new StatusListController(
            $this->statusListTokenProviderMock,
            new HttpContentNegotiator(),
            $this->statusListRateLimiterMock,
            $this->routesMock,
            $this->helpers,
            $this->loggerServiceMock,
        );
    }


    /**
     * @param array<string,string> $headers
     * @param array<string,string> $query
     */
    protected function request(array $headers = [], array $query = []): Request
    {
        $server = [];

        foreach ($headers as $name => $value) {
            $server['HTTP_' . strtoupper(str_replace('-', '_', $name))] = $value;
        }

        return new Request($query, [], [], [], [], $server);
    }


    public function testServesTheToken(): void
    {
        $response = $this->sut()->statusList($this->request(), self::LIST_ID);

        $this->assertSame(Response::HTTP_OK, $response->getStatusCode());
        $this->assertSame(self::TOKEN, $response->getContent());
        $this->assertSame(StatusListController::MEDIA_TYPE, $response->headers->get('Content-Type'));
    }


    /**
     * The specification recommends cross origin reads, and a browser based Relying Party which can not
     * read the response can not distinguish a revoked credential from a network failure.
     */
    public function testAlwaysAllowsCrossOriginReads(): void
    {
        $this->assertSame(
            '*',
            $this->sut()->statusList($this->request(), self::LIST_ID)->headers->get('Access-Control-Allow-Origin'),
        );
    }


    public function testAnnouncesHowLongTheResponseMayBeCached(): void
    {
        $response = $this->sut()->statusList($this->request(), self::LIST_ID);

        // Asserted as directives rather than as a string, since the header bag normalises and reorders
        // what it is given.
        $this->assertSame(43200, $response->getMaxAge());
        $this->assertTrue($response->headers->hasCacheControlDirective('public'));
        // Accept as well as Accept-Encoding: the response is publicly cacheable and an Accept which
        // excludes the media type is refused, so a cache keyed only on the encoding would serve a
        // stored token to a request the origin would have turned down.
        $this->assertSame('Accept, Accept-Encoding', $response->headers->get('Vary'));
        $this->assertMatchesRegularExpression('/^"[0-9a-f]{64}"$/', (string)$response->headers->get('ETag'));
    }


    /**
     * A list which is not served and one which never existed are the same answer.
     */
    public function testRespondsNotFoundForAnUnknownList(): void
    {
        $provider = $this->createMock(StatusListTokenProviderInterface::class);
        $provider->method('getToken')->willReturn(null);
        $this->statusListTokenProviderMock = $provider;

        $this->assertSame(
            Response::HTTP_NOT_FOUND,
            $this->sut()->statusList($this->request(), self::LIST_ID)->getStatusCode(),
        );
    }


    /**
     * Failing closed is the whole point: a token which no longer describes its list reports revoked
     * credentials as valid, so nothing at all is served when a fresh one can not be produced.
     */
    public function testRespondsServiceUnavailableWhenATokenCanNotBeProduced(): void
    {
        $provider = $this->createMock(StatusListTokenProviderInterface::class);
        $provider->method('getToken')->willThrowException(new StatusListException('signing key is gone'));
        $this->statusListTokenProviderMock = $provider;

        $response = $this->sut()->statusList($this->request(), self::LIST_ID);

        $this->assertSame(Response::HTTP_SERVICE_UNAVAILABLE, $response->getStatusCode());
        $this->assertNotNull($response->headers->get('Retry-After'));
        $this->assertEmpty($response->getContent());
    }


    /**
     * Answering a historical query with the current status would be worse than refusing it.
     */
    public function testRespondsNotImplementedForAHistoricalQuery(): void
    {
        $this->assertSame(
            Response::HTTP_NOT_IMPLEMENTED,
            $this->sut()->statusList($this->request([], ['time' => '1700000000']), self::LIST_ID)->getStatusCode(),
        );
    }


    public function testRespondsNotAcceptableWhenTheMediaTypeIsRefused(): void
    {
        $this->assertSame(
            Response::HTTP_NOT_ACCEPTABLE,
            $this->sut()->statusList($this->request(['Accept' => 'text/html']), self::LIST_ID)->getStatusCode(),
        );
    }


    public function testServesTheTokenWhenTheMediaTypeIsAccepted(): void
    {
        foreach (['*/*', 'application/*', StatusListController::MEDIA_TYPE] as $accept) {
            $this->assertSame(
                Response::HTTP_OK,
                $this->sut()->statusList($this->request(['Accept' => $accept]), self::LIST_ID)->getStatusCode(),
            );
        }
    }


    public function testRespondsTooManyRequestsWhenTheLimitIsReached(): void
    {
        $rateLimiter = $this->createMock(StatusListRateLimiter::class);
        $rateLimiter->method('allows')->willReturn(false);
        $this->statusListRateLimiterMock = $rateLimiter;

        $response = $this->sut()->statusList($this->request(), self::LIST_ID);

        $this->assertSame(Response::HTTP_TOO_MANY_REQUESTS, $response->getStatusCode());
        $this->assertSame('60', $response->headers->get('Retry-After'));
    }


    public function testCompressesTheBodyWhenTheClientAsksForIt(): void
    {
        $response = $this->sut()->statusList($this->request(['Accept-Encoding' => 'gzip']), self::LIST_ID);

        $this->assertSame('gzip', $response->headers->get('Content-Encoding'));
        $this->assertSame(self::TOKEN, gzdecode((string)$response->getContent()));
    }


    public function testSendsTheBodyUnencodedWhenNoCodingIsAcceptable(): void
    {
        $response = $this->sut()->statusList($this->request(['Accept-Encoding' => 'br']), self::LIST_ID);

        $this->assertNull($response->headers->get('Content-Encoding'));
        $this->assertSame(self::TOKEN, $response->getContent());
    }


    /**
     * The compressed and uncompressed responses are different representations of the same token, so a
     * cache which holds both must not confuse them.
     */
    public function testTheEntityTagDistinguishesTheEncodedResponse(): void
    {
        $plain = $this->sut()->statusList($this->request(), self::LIST_ID);
        $compressed = $this->sut()->statusList($this->request(['Accept-Encoding' => 'gzip']), self::LIST_ID);

        $this->assertNotSame($plain->headers->get('ETag'), $compressed->headers->get('ETag'));
    }


    public function testRespondsNotModifiedWhenTheClientAlreadyHasTheToken(): void
    {
        $entityTag = (string)$this->sut()->statusList($this->request(), self::LIST_ID)->headers->get('ETag');

        $response = $this->sut()->statusList($this->request(['If-None-Match' => $entityTag]), self::LIST_ID);

        $this->assertSame(Response::HTTP_NOT_MODIFIED, $response->getStatusCode());
        $this->assertSame($entityTag, $response->headers->get('ETag'));
        $this->assertSame(43200, $response->getMaxAge());
    }


    /**
     * If-None-Match compares weakly, so a tag the client stored as weak still matches.
     */
    public function testRespondsNotModifiedForAWeakenedEntityTag(): void
    {
        $entityTag = (string)$this->sut()->statusList($this->request(), self::LIST_ID)->headers->get('ETag');

        $this->assertSame(
            Response::HTTP_NOT_MODIFIED,
            $this->sut()->statusList(
                $this->request(['If-None-Match' => 'W/' . $entityTag]),
                self::LIST_ID,
            )->getStatusCode(),
        );
    }


    public function testRespondsNotModifiedForAWildcardValidator(): void
    {
        $this->assertSame(
            Response::HTTP_NOT_MODIFIED,
            $this->sut()->statusList($this->request(['If-None-Match' => '*']), self::LIST_ID)->getStatusCode(),
        );
    }


    public function testServesTheTokenWhenTheClientHoldsADifferentOne(): void
    {
        $this->assertSame(
            Response::HTTP_OK,
            $this->sut()->statusList(
                $this->request(['If-None-Match' => '"something-else"']),
                self::LIST_ID,
            )->getStatusCode(),
        );
    }


    /**
     * A client which stored the uncompressed copy and now asks for a compressed one is not holding the
     * representation which would be served.
     */
    public function testDoesNotReuseAValidatorAcrossContentCodings(): void
    {
        $plainTag = (string)$this->sut()->statusList($this->request(), self::LIST_ID)->headers->get('ETag');

        $this->assertSame(
            Response::HTTP_OK,
            $this->sut()->statusList(
                $this->request(['If-None-Match' => $plainTag, 'Accept-Encoding' => 'gzip']),
                self::LIST_ID,
            )->getStatusCode(),
        );
    }
}
