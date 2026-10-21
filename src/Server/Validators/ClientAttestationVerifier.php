<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\Validators;

use DateInterval;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Exceptions\AuthorizationException;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;
use SimpleSAML\Module\oidc\ValueAbstracts\ClientAttestationTrust;
use SimpleSAML\Module\oidc\ValueAbstracts\PresentedClientAttestation;
use SimpleSAML\OpenID\Codebooks\HttpHeadersEnum;
use SimpleSAML\OpenID\Codebooks\TokenEndpointAuthMethodsEnum;
use SimpleSAML\OpenID\Decorators\DateIntervalDecorator;
use SimpleSAML\OpenID\Exceptions\X509TrustStoreException;
use SimpleSAML\OpenID\OAuth2;
use SimpleSAML\OpenID\X509;
use SimpleSAML\OpenID\X509\CertificateChain;
use Throwable;

use function count;
use function hash;
use function hash_equals;
use function in_array;
use function json_encode;
use function microtime;
use function preg_match;
use function trim;

/**
 * Checks the Client Attestation and its PoP a request carries in the OAuth-Client-Attestation and
 * OAuth-Client-Attestation-PoP header fields (draft-ietf-oauth-attestation-based-client-auth-07, which OpenID4VCI
 * 1.0 Appendix E and HAIP 1.0 section 4.4.1 use), for the client the attestation names, which the caller looks up
 * between the two steps: AuthenticatedOAuth2ClientResolver::forClientAttestation().
 *
 * parse() makes check 1 of section 9 (one field of each, each holding one JWT), and the library's ClientAttestation
 * and ClientAttestationPop make, when they are built, checks 2, 3 and 6 and what of check 4 is not local policy,
 * along with the expiry of the attestation and an `iat` or `nbf` of either which lies in the future.
 *
 * verify() makes the rest, the cheap ones first, so that only an attestation for a client set up for attestation,
 * signed with an accepted algorithm by the client's attester, reaches the certificate path validation:
 * - check 4, both algorithms among those the module accepts (ModuleConfig::getClientAttestationSigningAlgorithms());
 * - the client registered with `token_endpoint_auth_method` `attest_jwt_client_auth`, and with the trust an
 *   administrator gave it (ClientAttestationTrust, D36 of the HAIP plan);
 * - check 5: the attestation's `iss` is that client's attester; its `x5c` validates against the client's trust
 *   anchors (X509\CertificatePathValidator), the certificate which issued the leaf holds the key the client pins
 *   for its issuing CA, the leaf names the attester's identity as the client pins it, and the attestation's
 *   signature verifies with the leaf's key. The issuing CA is pinned because a subject name is unique only among
 *   the certificates of one CA (RFC 5280 section 4.1.2.6): another provider under the same root, or under a
 *   sibling CA with the same name, can not sign for this client by asserting its attester's `iss`;
 * - check 7 and section 5.2 rule 4: the PoP's signature verifies with the attestation's `cnf.jwk`, and its `iss` is
 *   the attestation's `sub`;
 * - check 10: the PoP's `aud` holds this OP's issuer identifier;
 * - on one reading of the clock, taken after the path validation and the signatures, since those can take long
 *   enough for an attestation or a PoP to expire meanwhile: the attestation's `exp` with the module's timestamp
 *   validation leeway (section 5.1), the PoP's `iat` within PROOF_WINDOW_SECONDS of the present either way (checks
 *   9 and 12, section 10.6's sliding window), and the PoP's `exp`, when it has one, with that window as its leeway;
 * - check 12 and section 12.1, last, once everything else passed: the PoP's `jti` is remembered in the protocol
 *   cache for REPLAY_TTL_SECONDS, keyed on the client, the Client Instance Key and the `jti`, and a PoP seen before
 *   is refused. Without a protocol cache which keeps entries from one request to the next
 *   (ModuleConfig::isProtocolCacheKeptAcrossRequests()) nothing is remembered and replay is not checked, as for
 *   DPoP proofs; a record the cache does not keep fails the request as the OP's own failure. Not covered, as for
 *   DPoP proofs: two requests with one PoP at the same moment, an entry the cache evicts early or fails to read,
 *   and a cache of its own on each node of a cluster.
 *
 * Check 13, a `client_id` sent with the request equal to the attestation's `sub`, is the caller's, which reads the
 * request's parameters. Check 8 does not arise: the module offers no challenge endpoint (section 8), so it provided
 * no challenge, and a PoP's `challenge` is not looked at. Nor does check 11 beyond the attestation's expiry, the
 * module setting no freshness policy of its own, so `use_fresh_attestation` is never the answer. Revocation and the
 * attestation's `status` are not checked (D37 of the HAIP plan): a compromised attester is distrusted by changing or
 * removing the client's trust.
 *
 * A refusal is an AuthorizationException, which the caller answers as `invalid_client`. A failure of the OP's own
 * is a RuntimeException: the protocol cache failing, and a certificate path validation which could not run at all
 * (the library's X509TrustStoreException: a temporary directory which can not be written, say), which says
 * nothing about the chain.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\Server\Validators\ClientAttestationVerifierTest
 */
class ClientAttestationVerifier
{
    /**
     * How far a PoP's `iat` may lie from the present, in seconds, either way: the window of section 10.6, and the
     * FAPI 2.0 Security Profile's bounds for an `iat` in the future (section 5.3.2.1: accepted up to 10 seconds
     * ahead, refused more than 60 seconds ahead), as for DPoP proofs (DpopProofVerifier::PROOF_WINDOW_SECONDS). The
     * library's own checks of a PoP's `iat`, `nbf` and `exp` get it as their leeway, so that they agree.
     */
    public const int PROOF_WINDOW_SECONDS = 60;

    /**
     * How long a PoP's `jti` is remembered, in seconds. A PoP is accepted for the 120 seconds from
     * PROOF_WINDOW_SECONDS before its `iat` to as many after; the margin keeps a record written at the first moment
     * until after the last.
     */
    public const int REPLAY_TTL_SECONDS = 125;

    protected const string REPLAY_CACHE_KEY = 'client_attestation_pop_jti';

    /**
     * RFC 9110 section 11.2's token68, which section 6.1 makes the syntax of both field values: base64url segments
     * joined with dots for a JWT. A value with a comma in it is two field values joined into one.
     */
    protected const string TOKEN68_PATTERN = '/^[A-Za-z0-9\-._~+\/]+=*\z/';


    public function __construct(
        protected readonly OAuth2 $oAuth2,
        protected readonly X509 $x509,
        protected readonly ModuleConfig $moduleConfig,
        protected readonly ?ProtocolCache $protocolCache,
        protected readonly LoggerService $loggerService,
    ) {
    }


    /**
     * Whether the request carries either header field, whatever it holds: an attempt at attestation-based client
     * authentication, which has to succeed for the request to authenticate.
     */
    public function presentsClientAttestation(ServerRequestInterface $request): bool
    {
        return $request->getHeader(HttpHeadersEnum::OAuthClientAttestation->value) !== [] ||
        $request->getHeader(HttpHeadersEnum::OAuthClientAttestationPop->value) !== [];
    }


    /**
     * The library refuses an attestation or a PoP which has expired, or was issued too far in the future, on the
     * clock as it reads it here; verify() checks the expiry again, on the clock after its slow checks. Refusing an
     * expired one this early is sound, the clock only moving on.
     *
     * @return \SimpleSAML\Module\oidc\ValueAbstracts\PresentedClientAttestation|null Null for a request which
     * carries neither header field.
     * @throws \SimpleSAML\Module\oidc\Exceptions\AuthorizationException For a request which carries one of them
     * only, more than one of either, or values which are not a Client Attestation and its PoP.
     */
    public function parse(ServerRequestInterface $request): ?PresentedClientAttestation
    {
        if (!$this->presentsClientAttestation($request)) {
            return null;
        }

        $attestationToken = $this->singleJwt($request, HttpHeadersEnum::OAuthClientAttestation);
        $popToken = $this->singleJwt($request, HttpHeadersEnum::OAuthClientAttestationPop);

        try {
            $attestation = $this->oAuth2->clientAttestationFactory(
                $this->moduleConfig->getTimestampValidationLeeway(),
            )->fromToken($attestationToken);
            $clientId = $attestation->getSubject();
            $attestationExpiresAt = $attestation->getExpirationTimeNumericDate();
            $instanceKeyThumbprint = $attestation->getConfirmationJwkThumbprint();
        } catch (Throwable $throwable) {
            throw new AuthorizationException(
                'The Client Attestation is not a well-formed Client Attestation JWT, or has expired: ' .
                $throwable->getMessage(),
                previous: $throwable,
            );
        }

        try {
            $pop = $this->oAuth2->clientAttestationPopFactory(
                new DateInterval('PT' . self::PROOF_WINDOW_SECONDS . 'S'),
            )->fromToken($popToken);
            $popIssuedAt = $pop->getIssuedAtNumericDate();
            $popExpiresAt = $pop->getExpirationTimeNumericDate();
            $popJwtId = $pop->getJwtId();
        } catch (Throwable $throwable) {
            throw new AuthorizationException(
                'The Client Attestation PoP is not a well-formed Client Attestation PoP JWT, or has expired: ' .
                $throwable->getMessage(),
                previous: $throwable,
            );
        }

        return new PresentedClientAttestation(
            $attestation,
            $pop,
            $clientId,
            $attestationExpiresAt,
            $popIssuedAt,
            $popExpiresAt,
            $popJwtId,
            $instanceKeyThumbprint,
        );
    }


    /**
     * Section 9, check 1: "The HTTP request contains exactly one field OAuth-Client-Attestation and one field
     * OAuth-Client-Attestation-PoP", and "Both fields contain exactly one well-formed JWT".
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\AuthorizationException
     */
    protected function singleJwt(ServerRequestInterface $request, HttpHeadersEnum $header): string
    {
        $values = $request->getHeader($header->value);

        if ($values === []) {
            throw new AuthorizationException(sprintf('The request carries no %s header field.', $header->value));
        }

        if (count($values) > 1) {
            throw new AuthorizationException(
                sprintf('The request carries more than one %s header field.', $header->value),
            );
        }

        $value = trim($values[0], " \t");
        if (preg_match(self::TOKEN68_PATTERN, $value) !== 1) {
            throw new AuthorizationException(sprintf('The %s header field does not hold one JWT.', $header->value));
        }

        return $value;
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\AuthorizationException When the attestation or its PoP fails a
     * check for this client.
     * @throws \RuntimeException When the certificate path can not be validated at all, or the protocol cache can
     * not check the PoP for replay or does not keep its record.
     */
    public function verify(PresentedClientAttestation $presented, ClientEntityInterface $client): void
    {
        $attestation = $presented->getAttestation();
        $pop = $presented->getPop();
        $acceptedAlgorithms = $this->moduleConfig->getClientAttestationSigningAlgorithms();
        // Read outside the conversions below: an issuer this OP can not state is its own failure, not a verdict.
        $issuer = $this->moduleConfig->getIssuer();

        try {
            $attestationAlgorithm = $attestation->getAlgorithm();
            $popAlgorithm = $pop->getAlgorithm();
            $attester = $attestation->getIssuer();
            $x5c = $attestation->getX509CertificateChain();
        } catch (Throwable $throwable) {
            throw new AuthorizationException(
                'The Client Attestation or its PoP can not be read: ' . $throwable->getMessage(),
                previous: $throwable,
            );
        }

        if (!in_array($attestationAlgorithm, $acceptedAlgorithms, true)) {
            throw new AuthorizationException(
                sprintf(
                    'The Client Attestation is signed with an algorithm which is not accepted (%s).',
                    $attestationAlgorithm,
                ),
            );
        }

        if (!in_array($popAlgorithm, $acceptedAlgorithms, true)) {
            throw new AuthorizationException(
                sprintf(
                    'The Client Attestation PoP is signed with an algorithm which is not accepted (%s).',
                    $popAlgorithm,
                ),
            );
        }

        if ($client->getTokenEndpointAuthMethod() !== TokenEndpointAuthMethodsEnum::AttestJwtClientAuth->value) {
            throw new AuthorizationException(
                sprintf(
                    'The client is not registered to authenticate with %s.',
                    TokenEndpointAuthMethodsEnum::AttestJwtClientAuth->value,
                ),
            );
        }

        $trust = $this->trustOf($client);

        if ($attester !== $trust->getAttester()) {
            throw new AuthorizationException(
                sprintf('The Client Attestation was not issued by the attester of the client (iss %s).', $attester),
            );
        }

        if ($x5c === null) {
            throw new AuthorizationException(
                'The Client Attestation carries no x5c header parameter, so its attester can not be identified by ' .
                'its certificate.',
            );
        }

        $validatedPath = $this->validatedPath($x5c, $trust);

        try {
            $attestation->verifyWithX509CertificatePath($validatedPath);
        } catch (Throwable $throwable) {
            throw new AuthorizationException(
                'The Client Attestation signature does not verify with the key of its certificate: ' .
                $throwable->getMessage(),
                previous: $throwable,
            );
        }

        try {
            $pop->verifyWithClientAttestation($attestation);
            $isAddressedToThisOp = $pop->hasAudience($issuer);
        } catch (Throwable $throwable) {
            throw new AuthorizationException(
                'The Client Attestation PoP does not verify with the Client Instance Key, or is not for the client ' .
                'the Client Attestation names: ' . $throwable->getMessage(),
                previous: $throwable,
            );
        }

        if (!$isAddressedToThisOp) {
            throw new AuthorizationException('The Client Attestation PoP is not addressed to this issuer (aud).');
        }

        $this->ensureWithinTime($presented);

        $this->ensureNotReplayed($presented);

        $this->loggerService->debug(
            'Client Attestation accepted.',
            ['client_id' => $presented->getClientId(), 'jkt' => $presented->getInstanceKeyThumbprint()],
        );
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\AuthorizationException
     */
    protected function trustOf(ClientEntityInterface $client): ClientAttestationTrust
    {
        try {
            $trust = $client->getClientAttestationTrust();
        } catch (Throwable $throwable) {
            throw new AuthorizationException(
                'The client attestation trust of the client can not be read: ' . $throwable->getMessage(),
                previous: $throwable,
            );
        }

        return $trust ?? throw new AuthorizationException(
            'The client has no client attestation trust, so none of its attestations can be accepted.',
        );
    }


    /**
     * The attestation's certificate path, validated against the client's trust anchors, issued by the issuing CA
     * the client pins and naming the attester's identity the client pins.
     *
     * @param non-empty-list<non-empty-string> $x5c
     * @throws \SimpleSAML\Module\oidc\Exceptions\AuthorizationException
     * @throws \RuntimeException When the path validation can not run.
     */
    protected function validatedPath(array $x5c, ClientAttestationTrust $trust): CertificateChain
    {
        try {
            $trustAnchors = $this->x509->certificateFactory()->bundleFromPem($trust->getTrustAnchors());
            $this->x509->certificatePathValidator()->enforceTrustAnchors($trustAnchors);
        } catch (Throwable $throwable) {
            throw new AuthorizationException(
                'The trust anchors in the client attestation trust of the client can not be used: ' .
                $throwable->getMessage(),
                previous: $throwable,
            );
        }

        try {
            $validatedPath = $this->x509->certificatePathValidator()->validate(
                $this->x509->certificateFactory()->chainFromX5c($x5c),
                $trustAnchors,
            );
        } catch (X509TrustStoreException $x509TrustStoreException) {
            throw new RuntimeException(
                'Unable to validate the certificate chain of the Client Attestation: ' .
                $x509TrustStoreException->getMessage(),
                0,
                $x509TrustStoreException,
            );
        } catch (Throwable $throwable) {
            throw new AuthorizationException(
                'The certificate chain of the Client Attestation does not validate against the trust anchors of the ' .
                'client: ' . $throwable->getMessage(),
                previous: $throwable,
            );
        }

        // A validated path ends with its trust anchor, so the leaf always has a certificate after it: an
        // intermediate, or the anchor itself when the anchor issued the leaf.
        $leafIssuer = $validatedPath->getLeafIssuer();

        try {
            $isIssuedByThePinnedCa = $leafIssuer !== null &&
            hash_equals($trust->getIssuingCaPublicKeySha256(), $leafIssuer->getPublicKeySha256());
            $namesTheAttester = $validatedPath->getLeaf()->hasIdentity(
                $trust->getAttesterIdentityType(),
                $trust->getAttesterIdentity(),
            );
        } catch (Throwable $throwable) {
            throw new AuthorizationException(
                'The certificate of the Client Attestation can not be held to the client attestation trust of the ' .
                'client: ' . $throwable->getMessage(),
                previous: $throwable,
            );
        }

        if (!$isIssuedByThePinnedCa) {
            throw new AuthorizationException(
                'The certificate of the Client Attestation was not issued by the issuing CA the client pins.',
            );
        }

        if (!$namesTheAttester) {
            throw new AuthorizationException(
                sprintf(
                    'The certificate of the Client Attestation does not name the attester the client pins (%s).',
                    $trust->getAttesterIdentityType()->value,
                ),
            );
        }

        return $validatedPath;
    }


    /**
     * The time checks, on one reading of the clock taken now, once the slow checks are behind: the attestation is
     * not expired (RFC 7519 section 4.1.4, the leeway included, as the library has it), the PoP was created within
     * PROOF_WINDOW_SECONDS of now either way, and is not expired when it states an `exp`.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\AuthorizationException
     */
    protected function ensureWithinTime(PresentedClientAttestation $presented): void
    {
        $leeway = (float)DateIntervalDecorator::toSeconds($this->moduleConfig->getTimestampValidationLeeway());
        $window = (float)self::PROOF_WINDOW_SECONDS;
        $now = $this->currentTime();

        if ((float)$presented->getAttestationExpiresAt() + $leeway <= $now) {
            throw new AuthorizationException('The Client Attestation has expired.');
        }

        $popIssuedAt = (float)$presented->getPopIssuedAt();
        if ($popIssuedAt < $now - $window || $popIssuedAt > $now + $window) {
            throw new AuthorizationException(
                'The Client Attestation PoP was not created within the accepted time window.',
            );
        }

        $popExpiresAt = $presented->getPopExpiresAt();
        if ($popExpiresAt !== null && (float)$popExpiresAt + $window <= $now) {
            throw new AuthorizationException('The Client Attestation PoP has expired.');
        }
    }


    /**
     * The present, with the fraction of a second a NumericDate may carry too.
     */
    protected function currentTime(): float
    {
        return microtime(true);
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\AuthorizationException When the PoP was seen before.
     * @throws \RuntimeException When the cache can not check it, or does not keep its record.
     */
    protected function ensureNotReplayed(PresentedClientAttestation $presented): void
    {
        $protocolCache = $this->protocolCache;

        if (!$protocolCache instanceof ProtocolCache || !$this->moduleConfig->isProtocolCacheKeptAcrossRequests()) {
            $this->loggerService->debug(
                'Client Attestation PoPs are not checked for replay, since no protocol cache which keeps entries ' .
                'across requests is configured.',
            );

            return;
        }

        try {
            // One JSON array, so that no two different triples run together into the same string, hashed, so that a
            // long `jti` costs the cache nothing.
            $replayKey = [
                $presented->getClientId(),
                $presented->getInstanceKeyThumbprint(),
                $presented->getPopJwtId(),
            ];
            $keyElements = [self::REPLAY_CACHE_KEY, hash('sha256', json_encode($replayKey, JSON_THROW_ON_ERROR))];

            $seen = $protocolCache->has(...$keyElements);
            $kept = !$seen &&
            $protocolCache->set(true, self::REPLAY_TTL_SECONDS, ...$keyElements) &&
            $protocolCache->has(...$keyElements);
        } catch (Throwable $throwable) {
            throw new RuntimeException('Unable to check the Client Attestation PoP for replay.', 0, $throwable);
        }

        if ($seen) {
            throw new AuthorizationException('The Client Attestation PoP has been used before.');
        }

        if (!$kept) {
            throw new RuntimeException(
                'Unable to check the Client Attestation PoP for replay: the protocol cache did not keep its record.',
            );
        }
    }
}
