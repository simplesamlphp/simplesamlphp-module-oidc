<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\Validators;

use DateInterval;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;
use SimpleSAML\Module\oidc\ValueAbstracts\VerifiedDpopProof;
use SimpleSAML\OpenID\Codebooks\AccessTokenTypesEnum;
use SimpleSAML\OpenID\Codebooks\ErrorsEnum;
use SimpleSAML\OpenID\Codebooks\HttpHeadersEnum;
use SimpleSAML\OpenID\OAuth2;
use Throwable;

use function count;
use function hash;
use function in_array;
use function json_encode;
use function microtime;
use function preg_match;
use function trim;

/**
 * Checks the DPoP proof a request carries (RFC 9449). The protected resources use it through BearerTokenValidator,
 * for an access token presented under the DPoP scheme; the token endpoint (AccessTokenController) for every request
 * which carries a proof, whose key the grants then bind what they issue to; and the pushed authorization request
 * endpoint (PushedAuthorizationController), whose proof binds the authorization code (section 10.1).
 *
 * The library's DpopProof makes, when it is built, the checks of section 4.3 which need nothing but the proof. This
 * class makes the rest: one DPoP header field holding one JWT (checks 1 and 2), an algorithm the module accepts
 * (the local policy of check 5, ModuleConfig::getDpopSigningAlgorithms()), the signature by the proof's own key
 * (check 6), the method and the URI (checks 8 and 9), an `iat` no further than PROOF_WINDOW_SECONDS from the present
 * either way (check 11), and, with an access token, the token's hash in `ath` (the first half of check 12; whether
 * the key is the one the token is bound to is the caller's to compare, with the thumbprint returned). The module
 * issues no DPoP nonces, so none is checked (check 10).
 *
 * The URI a proof has to name is the one this OP publishes for the endpoint, never one rebuilt from the request,
 * since behind a proxy the URL a client called can only be told from headers anyone can send. So the OP is assumed
 * to be reached at the URLs it publishes, and a client which calls it under another name is refused. A proof sent
 * to the same endpoint under another name gains nothing over one replayed at the published URL: its `htu` still
 * has to name this endpoint, and the replay check is keyed on the published URL.
 *
 * Replay (section 11.1): the `jti` of a proof which passed every other check is remembered in the protocol cache
 * for REPLAY_TTL_SECONDS, keyed on the proof's key, the endpoint and the `jti`, and a proof seen before is
 * refused. Without a protocol cache which keeps entries from one request to the next
 * (ModuleConfig::isProtocolCacheKeptAcrossRequests()) nothing is remembered, and replay is not checked. A record
 * the cache does not report as stored, or which does not read back, fails the request as the OP's own failure
 * (`server_error`), since Symfony's adapters report a failed write rather than throw. Not covered: two requests
 * with one proof at the same moment (the cache is read and then written, as two operations), an entry the cache
 * evicts early or fails to read (both read as a proof not seen), and a cache of its own on each node of a cluster.
 *
 * A refusal is `invalid_dpop_proof`, with a description of this class's own naming the check which failed: the
 * library's messages may quote what the proof carried, so they go to the debug log only, and nothing else of a
 * proof is logged but the thumbprint of its key, at debug too; the access token never is. With an access token,
 * the request is to a protected resource, and the refusal is section 7.1's 401 with a DPoP challenge; without, it
 * is section 5's 400.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\Server\Validators\DpopProofVerifierTest
 */
class DpopProofVerifier
{
    /**
     * The request attribute the token endpoint puts the verified proof of a token request in, for the grants to
     * read (IssueAccessTokenTrait::getVerifiedDpopProof()).
     */
    public const string ATTRIBUTE_VERIFIED_PROOF = 'oidc_verified_dpop_proof';

    /**
     * How far a proof's `iat` may lie from the present, in seconds, either way. Section 11.1 has a server accept a
     * proof only for a limited time after its creation, and the FAPI 2.0 Security Profile (section 5.3.2.1) has it
     * accept an `iat` up to 10 seconds ahead and refuse one more than 60 seconds ahead. Fixed, whatever the
     * module's timestamp validation leeway; the library's own checks of `iat`, `nbf` and `exp` get it as their
     * leeway, so that they agree.
     */
    public const int PROOF_WINDOW_SECONDS = 60;

    /**
     * How long a proof's `jti` is remembered, in seconds. A proof is accepted for the 120 seconds from
     * PROOF_WINDOW_SECONDS before its `iat` to as many after, both ends included; the margin keeps a record written
     * at the first moment until after the last.
     */
    public const int REPLAY_TTL_SECONDS = 125;

    protected const string REPLAY_CACHE_KEY = 'dpop_jti';

    /**
     * RFC 9110 section 11.2's token68, which the JWS Compact Serialization of one JWT is: base64url segments joined
     * with dots. A value with a comma in it is two field values joined into one.
     */
    protected const string TOKEN68_PATTERN = '/^[A-Za-z0-9\-._~+\/]+=*\z/';


    public function __construct(
        protected readonly OAuth2 $oAuth2,
        protected readonly ModuleConfig $moduleConfig,
        protected readonly ?ProtocolCache $protocolCache,
        protected readonly LoggerService $loggerService,
    ) {
    }


    /**
     * @param string $endpointUrl The URL this OP publishes for the endpoint the request came to, which the proof's
     * `htu` has to name.
     * @param string|null $accessToken At a protected resource, the access token exactly as the request carried it,
     * which the proof's `ath` has to be the hash of; null at the token and pushed authorization request endpoints.
     * @return \SimpleSAML\Module\oidc\ValueAbstracts\VerifiedDpopProof|null Null for a request without a DPoP
     * header field.
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException `invalid_dpop_proof` for a proof which
     * fails a check, `server_error` for a failure of the OP's own.
     */
    public function verify(
        ServerRequestInterface $request,
        string $endpointUrl,
        ?string $accessToken,
    ): ?VerifiedDpopProof {
        $values = $request->getHeader(HttpHeadersEnum::DPoP->value);

        if ($values === []) {
            return null;
        }

        // Section 4.3 checks 1 and 2: "There is not more than one DPoP HTTP request header field", and its value
        // "is a single and well-formed JWT".
        if (count($values) > 1) {
            throw $this->refusal('The request carries more than one DPoP header field.', $accessToken);
        }

        $value = trim($values[0], " \t");
        if (preg_match(self::TOKEN68_PATTERN, $value) !== 1) {
            throw $this->refusal('The DPoP header field does not hold one JWT.', $accessToken);
        }

        $normalizedEndpointUrl = $this->oAuth2->helpers()->url()->normalizeHttpTargetUri($endpointUrl);
        if ($normalizedEndpointUrl === null) {
            throw OidcServerException::serverError(
                'The endpoint URL a DPoP proof is to be checked against is not a usable URL.',
            );
        }

        $dpopProofFactory = $this->oAuth2->dpopProofFactory(
            new DateInterval('PT' . self::PROOF_WINDOW_SECONDS . 'S'),
        );

        try {
            $proof = $dpopProofFactory->fromToken($value);
            $algorithm = $proof->getAlgorithm();
            $issuedAt = (float)$proof->getIssuedAtNumericDate();
            $matchesRequest = $proof->matchesHttpRequest($request->getMethod(), $endpointUrl);
            $matchesAccessToken = $accessToken === null || $proof->matchesAccessToken($accessToken);
            $jwtId = $proof->getJwtId();
            $jwkThumbprint = $proof->getJwkThumbprint();
        } catch (Throwable $throwable) {
            $this->loggerService->debug('DPoP proof refused: ' . $throwable->getMessage());
            throw $this->refusal(
                'The DPoP proof is not a well-formed DPoP proof JWT, or fails a check of RFC 9449 section 4.3.',
                $accessToken,
            );
        }

        if (!in_array($algorithm, $this->moduleConfig->getDpopSigningAlgorithms(), true)) {
            throw $this->refusal('The DPoP proof is signed with an algorithm which is not accepted.', $accessToken);
        }

        try {
            $proof->verifyWithEmbeddedKey();
        } catch (Throwable $throwable) {
            $this->loggerService->debug('DPoP proof refused: ' . $throwable->getMessage());
            throw $this->refusal('The DPoP proof signature does not verify with its key.', $accessToken);
        }

        if (!$matchesRequest) {
            throw $this->refusal(
                'The DPoP proof is not for this request: its htm or htu does not match.',
                $accessToken,
            );
        }

        // A NumericDate is at most 2^53 (Type::enforceNumericDate()), which a float holds exactly.
        $now = $this->currentTime();
        $window = (float)self::PROOF_WINDOW_SECONDS;
        if ($issuedAt < $now - $window || $issuedAt > $now + $window) {
            throw $this->refusal('The DPoP proof was not created within the accepted time window.', $accessToken);
        }

        if (!$matchesAccessToken) {
            throw $this->refusal('The DPoP proof does not carry the hash of the access token.', $accessToken);
        }

        $this->ensureNotReplayed($jwkThumbprint, $normalizedEndpointUrl, $jwtId, $accessToken);

        $this->loggerService->debug('DPoP proof accepted.', ['jkt' => $jwkThumbprint]);

        return new VerifiedDpopProof($proof, $jwkThumbprint);
    }


    /**
     * The present, with the fraction of a second a proof's `iat` may carry too.
     */
    protected function currentTime(): float
    {
        return microtime(true);
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    protected function ensureNotReplayed(
        string $jwkThumbprint,
        string $normalizedEndpointUrl,
        string $jwtId,
        ?string $accessToken,
    ): void {
        $protocolCache = $this->protocolCache;

        if (!$protocolCache instanceof ProtocolCache || !$this->moduleConfig->isProtocolCacheKeptAcrossRequests()) {
            $this->loggerService->debug(
                'DPoP proofs are not checked for replay, since no protocol cache which keeps entries across ' .
                'requests is configured.',
            );

            return;
        }

        try {
            // One JSON array, so that no two different triples run together into the same string, hashed, so that a
            // long `jti` costs the cache nothing.
            $keyElements = [
                self::REPLAY_CACHE_KEY,
                hash('sha256', json_encode([$jwkThumbprint, $normalizedEndpointUrl, $jwtId], JSON_THROW_ON_ERROR)),
            ];

            $seen = $protocolCache->has(...$keyElements);
            $kept = !$seen &&
            $protocolCache->set(true, self::REPLAY_TTL_SECONDS, ...$keyElements) &&
            $protocolCache->has(...$keyElements);
        } catch (Throwable $throwable) {
            throw OidcServerException::serverError('Unable to check the DPoP proof for replay.', $throwable);
        }

        if ($seen) {
            throw $this->refusal('The DPoP proof has been used before.', $accessToken);
        }

        if (!$kept) {
            throw OidcServerException::serverError(
                'Unable to check the DPoP proof for replay: the protocol cache did not keep its record.',
            );
        }
    }


    protected function refusal(string $description, ?string $accessToken): OidcServerException
    {
        return OidcServerException::invalidDpopProof(
            $description,
            $accessToken === null ? null : OidcServerException::buildChallenge(
                AccessTokenTypesEnum::DPoP,
                ErrorsEnum::InvalidDpopProof->value,
                $this->moduleConfig->getDpopSigningAlgorithms(),
            ),
        );
    }
}
