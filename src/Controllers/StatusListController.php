<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers;

use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\StatusList\Contracts\StatusListTokenProviderInterface;
use SimpleSAML\Module\oidc\StatusList\StatusListRateLimiter;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListTokenResult;
use SimpleSAML\Module\oidc\Utils\HttpContentNegotiator;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\Codebooks\JwtTypesEnum;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * Publishes one Status List Token.
 *
 * Deliberately not gated on the Verifiable Credential Issuance switch, unlike every other endpoint in
 * that family. Credentials already in wallets carry the URI this serves, and a Relying Party which can
 * not resolve it can not tell a valid credential from a revoked one. Turning issuance off has to stop
 * new credentials being issued, not make the existing ones unverifiable, so lists keep being served here
 * until their own lifecycle retires them.
 *
 * Unauthenticated, which is this deployment's chosen profile rather than a requirement: the
 * specification asks for an HTTP GET and says nothing about who may make it. The privacy property comes
 * from many credentials sharing one list, not from restricting who can fetch it.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\Controllers\StatusListControllerTest
 */
class StatusListController
{
    final public const string MEDIA_TYPE = 'application/' . JwtTypesEnum::StatusListJwt->value;

    /**
     * The only content coding offered.
     *
     * `deflate` is deliberately not offered. RFC 9110 defines it as the zlib format, but enough clients
     * historically sent and expected raw DEFLATE that which of the two a given client will accept is not
     * knowable from the header alone. gzip has no such ambiguity and is universally supported.
     */
    final public const string CONTENT_CODING_GZIP = 'gzip';

    /** Seconds a client is asked to wait after a request this endpoint could not answer. */
    protected const int RETRY_AFTER_SECONDS = 30;

    public function __construct(
        protected readonly StatusListTokenProviderInterface $statusListTokenProvider,
        protected readonly HttpContentNegotiator $httpContentNegotiator,
        protected readonly StatusListRateLimiter $statusListRateLimiter,
        protected readonly Routes $routes,
        protected readonly Helpers $helpers,
        protected readonly LoggerService $loggerService,
    ) {
    }

    /**
     * @param string $statusListId URL path parameter injected by the router.
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function statusList(Request $request, string $statusListId): Response
    {
        // Asking for the status as at some past moment is a distinct capability which this issuer does
        // not have. Saying so is the point: ignoring the parameter would answer with the current status
        // and let the caller believe it was a historical one.
        if ($request->query->has('time')) {
            return $this->routes->newResponse(null, Response::HTTP_NOT_IMPLEMENTED, $this->baseHeaders());
        }

        if (!$this->statusListRateLimiter->allows($request->getClientIp())) {
            return $this->routes->newResponse(
                null,
                Response::HTTP_TOO_MANY_REQUESTS,
                $this->baseHeaders(['Retry-After' => (string)StatusListRateLimiter::WINDOW_SECONDS]),
            );
        }

        if (!$this->httpContentNegotiator->acceptsMediaType($request->headers->get('Accept'), self::MEDIA_TYPE)) {
            return $this->routes->newResponse(null, Response::HTTP_NOT_ACCEPTABLE, $this->baseHeaders());
        }

        try {
            $result = $this->statusListTokenProvider->getToken($statusListId);
        } catch (Throwable $throwable) {
            // Fail closed. A token which no longer describes its list reports revoked credentials as
            // valid, so when one can not be produced the honest answer is that this is unavailable
            // right now -- never the last one that was produced.
            $this->loggerService->error(
                'Unable to produce a Status List Token, so nothing was served.',
                ['statusListId' => $statusListId, 'error' => $throwable->getMessage()],
            );

            return $this->routes->newResponse(
                null,
                Response::HTTP_SERVICE_UNAVAILABLE,
                $this->baseHeaders(['Retry-After' => (string)self::RETRY_AFTER_SECONDS]),
            );
        }

        if (!$result instanceof StatusListTokenResult) {
            return $this->routes->newResponse(null, Response::HTTP_NOT_FOUND, $this->baseHeaders());
        }

        return $this->respondWith($request, $result);
    }

    /**
     * @throws \Exception
     */
    protected function respondWith(Request $request, StatusListTokenResult $result): Response
    {
        // Decided before anything is compressed, because the entity tag has to name the representation
        // which would be served, and a request answered with 304 must not pay for compressing a body
        // that is then thrown away.
        //
        // Null here means "send it unencoded", and deliberately does not distinguish a client which
        // expressed no preference from one which excluded every coding including identity, with
        // `*;q=0` or an explicit `identity;q=0`. RFC 9110 would allow answering that second case with
        // 406. It is not answered that way on purpose: the request is self-defeating, no real client
        // makes it, and the cost of being wrong in that direction is a credential which cannot be
        // verified -- whereas the cost of serving the token anyway is nothing at all.
        $contentCoding = $this->httpContentNegotiator->preferredContentCoding(
            $request->headers->get('Accept-Encoding'),
            self::CONTENT_CODING_GZIP,
        );

        $entityTag = $result->getEntityTag($contentCoding);
        $now = $this->helpers->dateTime()->getUtc();

        $headers = $this->baseHeaders([
            'Cache-Control' => 'public, max-age=' . $result->getMaxAgeSeconds($now),
            'ETag' => $entityTag,
            // Accept-Encoding because the body differs by content coding, so a shared cache must not
            // hand one client's encoded copy to a client which asked for none.
            //
            // Accept because this response is publicly cacheable while an Accept which excludes the
            // media type is answered with 406. Without it a cache would serve a stored token to a
            // request the origin would have refused, so the refusal would hold only for requests which
            // reached the origin. It costs some cache efficiency, since Accept varies more widely than
            // Accept-Encoding does.
            'Vary' => 'Accept, Accept-Encoding',
        ]);

        if ($this->isCurrent($request->headers->get('If-None-Match'), $entityTag)) {
            return $this->routes->newResponse(null, Response::HTTP_NOT_MODIFIED, $headers);
        }

        $body = $result->getToken();
        $headers['Content-Type'] = self::MEDIA_TYPE;

        if ($contentCoding === self::CONTENT_CODING_GZIP) {
            $compressed = gzencode($body);

            // Failing to compress is not a reason to fail the request; the body is simply sent as it is,
            // without claiming an encoding it does not have. Announcing a coding not actually applied
            // would leave the client unable to read a perfectly good token.
            if (is_string($compressed)) {
                $body = $compressed;
                $headers['Content-Encoding'] = self::CONTENT_CODING_GZIP;
            } else {
                // The validator named the compressed representation, and this is not it. Leaving it
                // would give the same strong tag to two different bodies, so a client which cached this
                // one would later be told 304 for the compressed one and keep the wrong bytes.
                $headers['ETag'] = $result->getEntityTag();
            }
        }

        return $this->routes->newResponse($body, Response::HTTP_OK, $headers);
    }

    /**
     * Whether the copy the client already holds is the one which would be served.
     *
     * If-None-Match uses the weak comparison function, so a tag the client received and stored as weak
     * still matches the strong tag it came from.
     */
    protected function isCurrent(?string $ifNoneMatch, string $entityTag): bool
    {
        $ifNoneMatch = trim((string)$ifNoneMatch);

        if ($ifNoneMatch === '') {
            return false;
        }

        if ($ifNoneMatch === '*') {
            return true;
        }

        foreach (explode(',', $ifNoneMatch) as $candidate) {
            $candidate = trim($candidate);

            if (str_starts_with($candidate, 'W/')) {
                $candidate = substr($candidate, 2);
            }

            if ($candidate === $entityTag) {
                return true;
            }
        }

        return false;
    }

    /**
     * Headers every response from here carries.
     *
     * Cross origin reads are allowed on every outcome and not only on success, so that a browser based
     * Relying Party can tell a 404 from a 503 rather than seeing both as an opaque network failure.
     *
     * @param array<string,string> $headers
     * @return array<string,string>
     */
    protected function baseHeaders(array $headers = []): array
    {
        return array_merge(['Access-Control-Allow-Origin' => '*'], $headers);
    }
}
