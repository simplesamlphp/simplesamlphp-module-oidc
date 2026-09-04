<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\VerifiableCredentials;

use SimpleSAML\Module\oidc\Codebooks\VciIssuerIdentifierModeEnum;
use SimpleSAML\Module\oidc\Exceptions\OidcException;
use SimpleSAML\Module\oidc\Factories\DidFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\VciIssuerIdentifier;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\VciIssuerIdentity;
use SimpleSAML\OpenID\Did\DidUrl;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPair;
use Throwable;

/**
 * Works out how a signed artifact names its issuer and the key it was signed with.
 *
 * Both the identifier and the key pair are handed in rather than read from configuration here, and
 * that is the whole point of the signature. A Status List Token has to be identified the way the list
 * it belongs to was created, which is recorded on the list's own row, so a resolver which read today's
 * configuration would make every list already being served start emitting a different issuer the
 * moment somebody changed the setting - invalidating tokens wallets are in the middle of verifying.
 * The issuer URL is read from configuration, since under that mode it is the identity rather than a
 * choice between identities.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\VerifiableCredentials\VciIssuerIdentityResolverTest
 */
class VciIssuerIdentityResolver
{
    /**
     * The verification method a did:jwk document names its only key by, fixed by the method itself.
     */
    protected const string DID_JWK_FRAGMENT = '#0';


    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly DidFactory $didFactory,
    ) {
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     */
    public function resolve(VciIssuerIdentifier $identifier, SignatureKeyPair $signatureKeyPair): VciIssuerIdentity
    {
        return match ($identifier->getMode()) {
            VciIssuerIdentifierModeEnum::DidJwk => $this->forDidJwk($signatureKeyPair),
            VciIssuerIdentifierModeEnum::DidWeb => $this->forDidWeb(
                // Not null under this mode: VciIssuerIdentifier refuses that pairing when it is built.
                (string)$identifier->getDidWeb(),
                $signatureKeyPair,
            ),
            VciIssuerIdentifierModeEnum::Https => $this->forHttps($signatureKeyPair),
        };
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     */
    protected function forDidJwk(SignatureKeyPair $signatureKeyPair): VciIssuerIdentity
    {
        try {
            $didJwk = $this->didFactory->didJwkResolver()->generateDidJwkFromJwk(
                $signatureKeyPair->getKeyPair()->getPublicKey()->jwk()->all(),
            );
        } catch (Throwable $throwable) {
            throw new OidcException(
                'Unable to derive the did:jwk identifier for the signing key: ' . $throwable->getMessage(),
                (int)$throwable->getCode(),
                $throwable,
            );
        }

        return new VciIssuerIdentity(VciIssuerIdentifierModeEnum::DidJwk, $didJwk, $didJwk . self::DID_JWK_FRAGMENT);
    }


    /**
     * The key identifier is minted by the same code which builds the published DID document, rather
     * than assembled here, so a `kid` can not name a verification method the document does not carry.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     */
    protected function forDidWeb(string $didWeb, SignatureKeyPair $signatureKeyPair): VciIssuerIdentity
    {
        try {
            $keyId = $this->didFactory->didDocumentFactory()->verificationMethodIdFor(
                new DidUrl($didWeb),
                $signatureKeyPair->getKeyPair()->getKeyId(),
            )->getValue();
        } catch (Throwable $throwable) {
            throw new OidcException(
                'Unable to build the did:web verification method identifier for the signing key: ' .
                $throwable->getMessage(),
                (int)$throwable->getCode(),
                $throwable,
            );
        }

        return new VciIssuerIdentity(VciIssuerIdentifierModeEnum::DidWeb, $didWeb, $keyId);
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     */
    protected function forHttps(SignatureKeyPair $signatureKeyPair): VciIssuerIdentity
    {
        try {
            $issuer = $this->moduleConfig->getIssuer();
        } catch (Throwable $throwable) {
            throw new OidcException(
                'Unable to resolve the issuer URL to identify credentials by: ' . $throwable->getMessage(),
                (int)$throwable->getCode(),
                $throwable,
            );
        }

        $this->assertIssuerIsDiscoverable($issuer);

        return new VciIssuerIdentity(
            VciIssuerIdentifierModeEnum::Https,
            $issuer,
            $signatureKeyPair->getKeyPair()->getKeyId(),
        );
    }


    /**
     * Refuse an issuer URL which nothing could perform SD-JWT VC discovery against.
     *
     * Under this mode the `iss` claim is the whole of the key resolution story: a verifier inserts
     * `.well-known/jwt-vc-issuer` into it, fetches, and reads `jwks_uri` from what comes back. That
     * only works for an absolute https URL, and only where the value carries no query or fragment for
     * the insertion to land after.
     *
     * `getIssuer()` guarantees none of this. It falls back to the host of the current request when the
     * option is not set, so a deployment reached over plain HTTP - which is every deployment behind a
     * TLS terminating proxy that forwards the wrong scheme, and every development one - would otherwise
     * issue credentials naming an `http://` issuer. Refusing is the point: a credential which cannot be
     * verified securely is worse than one that was never issued, and this is the last moment anything
     * can tell.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     */
    protected function assertIssuerIsDiscoverable(string $issuer): void
    {
        $parts = parse_url($issuer);

        if (
            // parse_url() decomposes rather than validates: it hands back a scheme and a host for
            // "https:// issuer.example.org" too, with the space kept inside the host. So the value is
            // checked for being a URL at all before its parts are read.
            !filter_var($issuer, FILTER_VALIDATE_URL) ||
            !is_array($parts) ||
            // Compared lower cased because URI schemes are case insensitive, while parse_url() keeps
            // whatever case it was given. Only the comparison is normalised: the value itself is
            // emitted exactly as configured, since the issuer metadata publishes that same string and
            // a verifier matching the two byte for byte must not see them disagree.
            strtolower($parts['scheme'] ?? '') !== 'https' ||
            (($parts['host'] ?? '') === '') ||
            array_key_exists('query', $parts) ||
            array_key_exists('fragment', $parts)
        ) {
            throw new OidcException(
                sprintf(
                    'Credentials are configured to name this issuer by its URL, but "%s" is not one a ' .
                    'verifier could discover keys through: it has to be an absolute https URL carrying ' .
                    'no query and no fragment.',
                    $issuer,
                ),
            );
        }
    }
}
