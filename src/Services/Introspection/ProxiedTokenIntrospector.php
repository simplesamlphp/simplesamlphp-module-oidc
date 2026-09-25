<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Services\Introspection;

use SensitiveParameter;
use SimpleSAML\Module\oidc\Codebooks\IntrospectionCallerRoleEnum;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Exceptions\UpstreamIntrospectionException;
use SimpleSAML\Module\oidc\Factories\IntrospectionReleasePolicyFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\ValueAbstracts\IntrospectedTokenOrigin;
use SimpleSAML\Module\oidc\ValueAbstracts\IntrospectionAuthorization;
use SimpleSAML\Module\oidc\ValueAbstracts\IntrospectionUpstream;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Helpers;
use SimpleSAML\OpenID\Jws\ParsedJws;

/**
 * Answers for a token this OP did not issue, by asking an authorization server it trusts: AARC-G052 proxied token
 * introspection, this OP acting as "AS1".
 *
 * Every refusal is an inactive answer (null here): G052 section 2.4 has AS1 answer "active" false for a token "not
 * valid for use by the RS making the request". A failure to get an answer is not a refusal and is thrown instead:
 * the token may well be active, and an inactive answer is one the resource server may cache. A deployment which
 * needs G052's literal reading - inactive whenever no trusted AS could validate the token, a transient failure
 * included - turns that on in the configuration.
 */
class ProxiedTokenIntrospector
{
    /**
     * Longest token this OP will send upstream, in bytes. A JWT access token carrying a long entitlement list is a
     * few kilobytes; anything past this is not a token worth a request to the hub.
     */
    public const int MAX_TOKEN_LENGTH = 16384;

    /**
     * How much of a value from a presented token or an upstream answer is repeated in a log line.
     */
    protected const int MAX_LOGGED_VALUE_LENGTH = 200;


    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly LoggerService $loggerService,
        protected readonly ClientRepository $clientRepository,
        protected readonly UpstreamIntrospectionClient $upstreamIntrospectionClient,
        protected readonly IntrospectionReleasePolicyFactory $introspectionReleasePolicyFactory,
        protected readonly Helpers $helpers,
    ) {
    }


    /**
     * @param \SimpleSAML\OpenID\Jws\ParsedJws $parsedJws The presented token, parsed and not verified, which names
     * an issuer other than this OP. G052 section 4: "Entities performing proxied token introspection are not
     * required to validate the signature of the token"; the authorization server asked about it does.
     * @return ?array<array-key, mixed> The answer for this caller, or null to answer the token as inactive.
     * @throws \SimpleSAML\Module\oidc\Exceptions\UpstreamIntrospectionException When no answer was had from
     * upstream; already logged.
     * @throws \SimpleSAML\Error\ConfigurationError When an upstream or the release policy is misconfigured.
     * @throws \Throwable Whatever the release policy or the storage throws.
     */
    public function introspect(
        #[SensitiveParameter]
        string $token,
        ParsedJws $parsedJws,
        ?string $tokenTypeHint,
        IntrospectionAuthorization $caller,
    ): ?array {
        $tokenIssuer = $parsedJws->getIssuer() ?? '(none)';

        // Only a resource server's question travels upstream. The hub asking about a token this OP did not issue
        // would be its own question coming back; a client or an administrator has no business with other
        // authorization servers' tokens here.
        if ($caller->getRole() !== IntrospectionCallerRoleEnum::ResourceServer) {
            return $this->inactive(
                $caller,
                $tokenIssuer,
                'only a resource server\'s question about such a token is introspected upstream',
            );
        }

        $refusal = $this->refusalBeforeForwarding($token, $parsedJws);
        if (!is_null($refusal)) {
            return $this->inactive($caller, $tokenIssuer, $refusal);
        }

        $callerClient = $this->clientRepository->findById($caller->getCallerId());

        if (!$callerClient instanceof ClientEntityInterface) {
            return $this->inactive($caller, $tokenIssuer, 'the resource server\'s own client record is gone');
        }

        $foreignIssuerList = $callerClient->getIntrospectionForeignIssuerList();

        // Refusing on an issuer nobody verified is safe: a forger can only refuse themselves.
        if (!is_null($foreignIssuerList) && !$foreignIssuerList->permits($tokenIssuer)) {
            return $this->inactive($caller, $tokenIssuer, 'the issuer is not permitted for this resource server');
        }

        $upstream = $this->moduleConfig->getApiOAuth2TokenIntrospectionUpstreamFor($tokenIssuer);
        if (is_null($upstream)) {
            return $this->inactive($caller, $tokenIssuer, 'no upstream authorization server is configured for it');
        }

        $answer = $this->askUpstream($upstream, $token, $tokenTypeHint, $caller, $tokenIssuer);

        if (is_null($answer)) {
            return null;
        }

        if ($answer['active'] !== true) {
            return $this->inactive($caller, $tokenIssuer, 'the upstream authorization server answered it inactive');
        }

        // Shape alone does not make a JWT a bearer token. G052 section 2.4's own example: a token "not locally
        // issued and ... of an OAuth 2.0 token type ... which cannot be used as an OAuth 2.0 bearer token". Absent
        // is accepted, as RFC 7662 section 2.2 makes the member optional.
        $tokenType = $this->stringMember($answer, 'token_type');
        if (!is_null($tokenType) && strcasecmp($tokenType, 'Bearer') !== 0) {
            return $this->inactive(
                $caller,
                $tokenIssuer,
                sprintf('the upstream reports a token type of %s', $this->forLog($tokenType)),
            );
        }

        // The upstream's 'iss' is the one to rely on: G052 section 3 forbids a proxy to change it, and the token's
        // own was never verified. It is optional (RFC 7662 section 2.2), and an empty one names no issuer either.
        $upstreamIssuer = $this->stringMember($answer, 'iss');
        $upstreamIssuer = $upstreamIssuer === '' ? null : $upstreamIssuer;

        // This OP answers for its own tokens itself, and the presented one did not name it; an upstream which says
        // otherwise is not to be passed on as this OP's word about its own token.
        if ($upstreamIssuer === $this->moduleConfig->getIssuer()) {
            return $this->inactive(
                $caller,
                $tokenIssuer,
                'the upstream names this OP as the issuer of a token which does not name it',
            );
        }

        if (!is_null($upstreamIssuer) && $upstreamIssuer !== $tokenIssuer) {
            $this->loggerService->warning(
                sprintf(
                    'A token presented as issued by %s was answered upstream as issued by %s; the upstream\'s ' .
                    'is used.',
                    $this->forLog($tokenIssuer),
                    $this->forLog($upstreamIssuer),
                ),
            );
        }

        if (!is_null($foreignIssuerList)) {
            if (is_null($upstreamIssuer)) {
                return $this->inactive(
                    $caller,
                    $tokenIssuer,
                    'the upstream answer names no issuer, so the issuer list for this resource server can not ' .
                    'be satisfied',
                );
            }

            if (!$foreignIssuerList->permits($upstreamIssuer)) {
                return $this->inactive(
                    $caller,
                    $upstreamIssuer,
                    'the issuer the upstream names is not permitted for this resource server',
                );
            }
        }

        $origin = IntrospectedTokenOrigin::foreign($upstreamIssuer ?? $tokenIssuer, !is_null($upstreamIssuer));
        $grantedScopes = $this->scopesOf($answer);

        $decision = $this->introspectionReleasePolicyFactory->build()->decide(
            $caller,
            $origin,
            $grantedScopes,
            $answer,
        );

        if ($decision->isDenied()) {
            $this->loggerService->notice(
                sprintf(
                    'The introspection release policy denies %s %s the answer about a token issued by %s. ' .
                    'Answering as if the token was not active.',
                    $caller->getRole()->value,
                    $caller->getCallerId(),
                    $this->forLog($origin->getIssuer()),
                ),
            );

            return null;
        }

        // On this path the claims are the issuer's, and which of them a scope carries is the issuer's mapping, not
        // this OP's: narrowing 'scope' removes no claim, and a policy which narrows it names the claims to
        // withhold itself. The withheld members go last, as on the local path.
        $releasedScopes = $decision->releasedScopesOf($grantedScopes);
        if ($releasedScopes !== $grantedScopes) {
            if ($releasedScopes === []) {
                unset($answer['scope']);
            } else {
                $answer['scope'] = implode(' ', $releasedScopes);
            }
        }

        return $decision->withholdFrom($answer);
    }


    /**
     * The upstream's answer, or null when a failure to get one is to be answered as an inactive token.
     *
     * @return ?array<string, mixed>
     * @throws \SimpleSAML\Module\oidc\Exceptions\UpstreamIntrospectionException
     */
    protected function askUpstream(
        IntrospectionUpstream $upstream,
        #[SensitiveParameter]
        string $token,
        ?string $tokenTypeHint,
        IntrospectionAuthorization $caller,
        string $tokenIssuer,
    ): ?array {
        try {
            return $this->upstreamIntrospectionClient->introspect($upstream, $token, $tokenTypeHint);
        } catch (UpstreamIntrospectionException $exception) {
            // This OP's own credentials or configuration are wrong, and every question will fail the same way
            // until somebody fixes it.
            $exception->isOwnFault() ?
            $this->loggerService->critical($exception->getMessage()) :
            $this->loggerService->error($exception->getMessage());

            if (!$this->moduleConfig->getApiOAuth2TokenIntrospectionUpstreamFailureAnswersInactive()) {
                throw $exception;
            }

            $this->inactive(
                $caller,
                $tokenIssuer,
                'no answer was had from upstream, and such failures are configured to answer as an inactive token',
            );

            return null;
        }
    }


    /**
     * Hygiene before anything is sent upstream, not verification: G052 section 4 does not require a proxy to
     * validate the signature, but a token it could never answer for is not worth the hub's time.
     *
     * @return ?string Why the token is refused, or null when it may be sent.
     * @throws \SimpleSAML\OpenID\Exceptions\OpenIdException
     */
    protected function refusalBeforeForwarding(string $token, ParsedJws $parsedJws): ?string
    {
        if (strlen($token) > self::MAX_TOKEN_LENGTH) {
            return sprintf('it is longer than %d bytes', self::MAX_TOKEN_LENGTH);
        }

        // G052 section 4, after RFC 9068 section 2.1: signed JWT access tokens "MUST NOT use "none" as the signing
        // algorithm".
        // Read as it stands rather than through getAlgorithm(), which refuses any algorithm this library does not
        // implement: whether the issuer's is one is for the authorization server which verifies the token to say.
        /** @var mixed $algorithm */
        $algorithm = $parsedJws->getHeaderClaim(ClaimsEnum::Alg->value);
        if (!is_string($algorithm) || $algorithm === '' || strcasecmp($algorithm, 'none') === 0) {
            return 'it names no signing algorithm, or "none"';
        }

        // Only ever used to pick an upstream from configuration, never to reach anything, but a value which is not
        // an https URL is not an issuer identifier (RFC 8414 section 2).
        $tokenIssuer = $parsedJws->getIssuer();
        if (is_null($tokenIssuer) || !$this->helpers->url()->isIssuerIdentifier($tokenIssuer)) {
            return 'its issuer is not an https URL without a user, a password, a query or a fragment';
        }

        return null;
    }


    /**
     * @param array<array-key, mixed> $answer
     * @return string[]
     */
    protected function scopesOf(array $answer): array
    {
        $scope = $this->stringMember($answer, 'scope');

        if (is_null($scope)) {
            return [];
        }

        return array_values(array_filter(explode(' ', $scope), fn(string $scopeToken): bool => $scopeToken !== ''));
    }


    /**
     * A member of the upstream answer, when it is a string; the upstream client refused an answer in which a
     * standard member has another type.
     *
     * @param array<array-key, mixed> $answer
     */
    protected function stringMember(array $answer, string $member): ?string
    {
        /** @var mixed $value */
        $value = $answer[$member] ?? null;

        return is_string($value) ? $value : null;
    }


    /**
     * A value taken from a presented token or an upstream answer, made safe to write into a log line: bounded,
     * and in printable ASCII, so that a line break in a forged 'iss' can not forge a log entry.
     */
    protected function forLog(string $value): string
    {
        $printable = (string)preg_replace('/[^\x20-\x7E]/', '?', $value);

        return strlen($printable) > self::MAX_LOGGED_VALUE_LENGTH ?
        substr($printable, 0, self::MAX_LOGGED_VALUE_LENGTH) . '...' :
        $printable;
    }


    /**
     * Logs why, and answers as an inactive token. The resource server is told nothing of the reason (RFC 7662
     * section 2.2: the authorization server "SHOULD NOT include any additional information about an inactive
     * token, including why the token is inactive").
     */
    protected function inactive(IntrospectionAuthorization $caller, string $issuer, string $reason): null
    {
        $this->loggerService->info(
            sprintf(
                'Token issued by %s, asked about by %s %s: answering as if the token was not active, because %s.',
                $this->forLog($issuer),
                $caller->getRole()->value,
                $caller->getCallerId(),
                $reason,
            ),
        );

        return null;
    }
}
