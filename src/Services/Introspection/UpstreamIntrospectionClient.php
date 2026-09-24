<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Services\Introspection;

use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\RequestOptions;
use JsonException;
use SensitiveParameter;
use SimpleSAML\Module\oidc\Exceptions\UpstreamIntrospectionException;
use SimpleSAML\Module\oidc\Factories\DestinationPolicyFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\ValueAbstracts\IntrospectionUpstream;
use SimpleSAML\OpenID\Codebooks\ClientAuthenticationMethodsEnum;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Decorators\HttpClientDecorator;
use SimpleSAML\OpenID\Exceptions\DestinationPolicyException;
use SimpleSAML\OpenID\Exceptions\InvalidValueException;
use SimpleSAML\OpenID\Factories\HttpClientDecoratorFactory;
use SimpleSAML\OpenID\Helpers;
use stdClass;
use Throwable;

/**
 * Asks an upstream authorization server about a token, as an OAuth 2.0 client of it (AARC-G052 section 2.2: AS1
 * calls "the introspection endpoint of another AS it has a trust relationship with"), and hands back the answer
 * once it is known to be an introspection response.
 *
 * The request is this OP's own: its own credentials, the token, and the caller's token_type_hint, which is an
 * optimisation the upstream may use or ignore (RFC 7662 section 2.1) and tells this OP nothing. The caller's
 * credentials are never forwarded. It goes through the deployment's outbound destination policy, over https,
 * without following redirects, within short timeouts - a worker waiting on a degraded hub is a worker not
 * answering anyone else - and with the answer's size bounded.
 */
class UpstreamIntrospectionClient
{
    /**
     * An introspection response is a small JSON object; this leaves room for a long entitlement list.
     */
    public const int MAX_RESPONSE_BYTES = 102400;

    /**
     * RFC 7662 section 2.2 members given a JSON string type there. A member present with another type is not a
     * response this OP can vouch for, so the answer is refused as a whole rather than passed on or trimmed.
     */
    protected const array STRING_MEMBERS = ['scope', 'client_id', 'username', 'token_type', 'sub', 'iss', 'jti'];

    /**
     * RFC 7662 section 2.2 members given an integer timestamp type there.
     */
    protected const array NUMERIC_DATE_MEMBERS = ['exp', 'iat', 'nbf'];

    /**
     * The protocol HTTP client options an upstream request takes over: how the upstream is reached (a proxy, the
     * HTTP version, the address family) and trusted (a CA bundle, a client certificate). Nothing which adds to the
     * request itself - credentials, headers, a body, cURL options - is taken over, so that the only credentials
     * sent are the upstream's own.
     */
    protected const array INHERITED_HTTP_CLIENT_OPTIONS = [
        RequestOptions::VERIFY,
        RequestOptions::CERT,
        RequestOptions::SSL_KEY,
        RequestOptions::PROXY,
        RequestOptions::VERSION,
        RequestOptions::FORCE_IP_RESOLVE,
        RequestOptions::CRYPTO_METHOD,
    ];

    /**
     * Nesting an answer may have. An introspection response is a flat object with the odd claim a level or two
     * deep.
     */
    protected const int MAX_ANSWER_DEPTH = 64;


    /** @var array<string, \SimpleSAML\OpenID\Decorators\HttpClientDecorator> Per upstream issuer. */
    protected array $httpClients = [];


    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly DestinationPolicyFactory $destinationPolicyFactory,
        protected readonly HttpClientDecoratorFactory $httpClientDecoratorFactory,
        protected readonly Helpers $helpers,
    ) {
    }


    /**
     * @return array<string, mixed> The upstream's answer: `['active' => false]` for an inactive token, whatever
     * else the upstream said about it; for an active one, the whole answer, its standard members checked.
     * @throws \SimpleSAML\Module\oidc\Exceptions\UpstreamIntrospectionException When there is no such answer.
     */
    public function introspect(
        IntrospectionUpstream $upstream,
        #[SensitiveParameter]
        string $token,
        ?string $tokenTypeHint,
    ): array {
        $httpClient = $this->httpClientFor($upstream);

        $formParams = ['token' => $token];

        if (!is_null($tokenTypeHint)) {
            $formParams['token_type_hint'] = $tokenTypeHint;
        }

        $headers = ['Accept' => 'application/json'];

        if ($upstream->getClientAuthenticationMethod() === ClientAuthenticationMethodsEnum::ClientSecretPost) {
            $formParams['client_id'] = $upstream->getClientId();
            $formParams['client_secret'] = $upstream->getClientSecret();
        } else {
            // RFC 6749 section 2.3.1: each is form-urlencoded before the two are joined and base64 encoded.
            $headers['Authorization'] = 'Basic ' . base64_encode(
                urlencode($upstream->getClientId()) . ':' . urlencode($upstream->getClientSecret()),
            );
        }

        try {
            $response = $httpClient->request(
                HttpMethodsEnum::POST,
                $upstream->getIntrospectionEndpoint(),
                [
                    RequestOptions::FORM_PARAMS => $formParams,
                    RequestOptions::HEADERS => $headers,
                    RequestOptions::ALLOW_REDIRECTS => false,
                    // The status of a refusal is what tells this OP's fault from the upstream's, and it travels
                    // with Guzzle's exception for it.
                    RequestOptions::HTTP_ERRORS => true,
                ],
                self::MAX_RESPONSE_BYTES,
            );
            $body = $httpClient->readResponseBodyAsString($response, self::MAX_RESPONSE_BYTES);
        } catch (DestinationPolicyException $exception) {
            throw UpstreamIntrospectionException::ownFault(
                sprintf(
                    'The outbound destination policy refuses the introspection endpoint of %s: %s',
                    $upstream->getIssuer(),
                    $exception->getMessage(),
                ),
                $exception,
            );
        } catch (Throwable $exception) {
            $statusCode = $this->findStatusCode($exception);

            if (in_array($statusCode, [401, 403], true)) {
                throw UpstreamIntrospectionException::ownFault(
                    sprintf(
                        'The introspection endpoint of %s refused this OP\'s credentials (HTTP %d).',
                        $upstream->getIssuer(),
                        $statusCode,
                    ),
                    $exception,
                );
            }

            throw UpstreamIntrospectionException::unavailable(
                sprintf(
                    'No answer from the introspection endpoint of %s: %s',
                    $upstream->getIssuer(),
                    $exception->getMessage(),
                ),
                $exception,
            );
        }

        return $this->readAnswer($upstream, $body);
    }


    /**
     * @return array<string, mixed>
     * @throws \SimpleSAML\Module\oidc\Exceptions\UpstreamIntrospectionException
     */
    protected function readAnswer(IntrospectionUpstream $upstream, string $body): array
    {
        try {
            // Decoded as objects, so that an object is told apart from a list: at the top, where RFC 7662 requires
            // an object, and inside, where a member keeps the shape the upstream gave it ("{}" is not "[]", and
            // {"0": "a"} is not a list).
            $decoded = json_decode($body, false, self::MAX_ANSWER_DEPTH, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw $this->malformed($upstream, 'not JSON', $exception);
        }

        if (!$decoded instanceof stdClass) {
            throw $this->malformed($upstream, 'not a JSON object');
        }

        $answer = get_object_vars($decoded);

        $active = $answer['active'] ?? null;

        if (!is_bool($active)) {
            throw $this->malformed($upstream, "no boolean 'active' member");
        }

        // Nothing else about an inactive token is passed on, whatever the upstream included: AARC-G052 section 3
        // has an inactive answer carry no additional information about the token.
        if (!$active) {
            return ['active' => false];
        }

        // With the library's own checks for a JSON string and an RFC 7519 NumericDate, the ones it applies to the
        // claims of a JWT.
        $type = $this->helpers->type();
        $member = null;

        // The library's message repeats the value, which is the upstream's to choose, so the one logged names the
        // member only.
        try {
            foreach (self::STRING_MEMBERS as $member) {
                if (array_key_exists($member, $answer)) {
                    $type->enforceString($answer[$member], $member);
                }
            }

            // RFC 7662 section 2.2 calls these integer timestamps. A JSON number with a fraction is accepted too, as
            // a JWT NumericDate may carry one (RFC 7519 section 2), and passed on as it came.
            foreach (self::NUMERIC_DATE_MEMBERS as $member) {
                if (array_key_exists($member, $answer)) {
                    $type->enforceNumericDate($answer[$member], $member);
                }
            }

            // A string or a list of strings, as for the JWT claim (RFC 7519 section 4.1.3). A JSON object is
            // neither, whatever its keys: it was decoded into an object above.
            $member = 'aud';
            if (array_key_exists($member, $answer) && !is_string($answer[$member])) {
                /** @psalm-suppress MixedAssignment Each entry is checked on the next line. */
                foreach ($type->enforceList($answer[$member], $member) as $audience) {
                    $type->enforceString($audience, $member);
                }
            }
        } catch (InvalidValueException $exception) {
            throw $this->malformed(
                $upstream,
                sprintf("'%s' does not have the type RFC 7662 section 2.2 gives it", (string)$member),
                $exception,
            );
        }

        // What is passed on is encoded again for the caller, which a number too large for a float (1e400, read as
        // INF) would make impossible.
        try {
            /** @psalm-suppress UnusedFunctionCall Called for the exception alone. */
            json_encode($answer, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw $this->malformed($upstream, 'it can not be passed on as JSON', $exception);
        }

        return $answer;
    }


    protected function malformed(
        IntrospectionUpstream $upstream,
        string $reason,
        ?Throwable $previous = null,
    ): UpstreamIntrospectionException {
        return UpstreamIntrospectionException::malformedResponse(
            sprintf(
                'The introspection endpoint of %s answered with an unusable response: %s.',
                $upstream->getIssuer(),
                $reason,
            ),
            $previous,
        );
    }


    /**
     * The HTTP status of the response a failure carries, looked for along the exception chain: the library
     * wraps Guzzle's own exception, which holds the response.
     */
    protected function findStatusCode(Throwable $throwable): ?int
    {
        $candidate = $throwable;

        // Bounded, so that a chain which loops back on itself can not hang the search.
        for ($depth = 0; $depth < 10 && !is_null($candidate); $depth++) {
            if ($candidate instanceof RequestException && $candidate->hasResponse()) {
                return $candidate->getResponse()?->getStatusCode();
            }

            $candidate = $candidate->getPrevious();
        }

        return null;
    }


    /**
     * One client per upstream, built on first use, with the upstream's own timeouts over the transport options of
     * the deployment's protocol HTTP client options (a CA bundle, a proxy), and redirects never followed.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\UpstreamIntrospectionException When this OP's own configuration
     * can not produce a client: the destination policy or the HTTP client options.
     */
    protected function httpClientFor(IntrospectionUpstream $upstream): HttpClientDecorator
    {
        if (isset($this->httpClients[$upstream->getIssuer()])) {
            return $this->httpClients[$upstream->getIssuer()];
        }

        try {
            return $this->httpClients[$upstream->getIssuer()] = $this->httpClientDecoratorFactory->build(
                httpClientConfig: array_merge(
                    array_intersect_key(
                        $this->moduleConfig->getProtocolHttpClientOptions(),
                        array_flip(self::INHERITED_HTTP_CLIENT_OPTIONS),
                    ),
                    [
                        RequestOptions::CONNECT_TIMEOUT => $upstream->getConnectTimeout(),
                        RequestOptions::TIMEOUT => $upstream->getTimeout(),
                        RequestOptions::ALLOW_REDIRECTS => false,
                    ],
                ),
                maxFetchSizeBytes: self::MAX_RESPONSE_BYTES,
                destinationPolicy: $this->destinationPolicyFactory->build(),
            );
        } catch (Throwable $exception) {
            throw UpstreamIntrospectionException::ownFault(
                sprintf(
                    'No HTTP client could be built for the introspection endpoint of %s: %s',
                    $upstream->getIssuer(),
                    $exception->getMessage(),
                ),
                $exception,
            );
        }
    }
}
