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
            $didJwk = $this->didFactory->build()->didJwkResolver()->generateDidJwkFromJwk(
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
            $keyId = $this->didFactory->build()->didDocumentFactory()->verificationMethodIdFor(
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

        return new VciIssuerIdentity(
            VciIssuerIdentifierModeEnum::Https,
            $issuer,
            $signatureKeyPair->getKeyPair()->getKeyId(),
        );
    }
}
