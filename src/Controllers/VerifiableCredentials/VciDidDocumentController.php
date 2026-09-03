<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers\VerifiableCredentials;

use SimpleSAML\Module\oidc\Factories\DidFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\Codebooks\VerificationMethodTypeEnum;
use SimpleSAML\OpenID\Codebooks\VerificationRelationshipEnum;
use SimpleSAML\OpenID\Did\DidUrl;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * Publishes the DID document for this deployment's did:web identifier.
 *
 * Deliberately not gated on the Verifiable Credential Issuance switch, on the same reasoning as the
 * Status List endpoint. A credential issued under a did:web identity states that identity as its `iss`
 * and names its signing key by a `kid` inside this document, so this is the only way to obtain the key
 * which signed it. Withholding the document therefore does not stop credentials being issued -- it
 * stops the ones already issued from ever being verified again.
 *
 * For the same reason the document is served while the identifier is configured, whatever the issuer
 * identity mode currently is. A deployment which has moved on to another mode stops signing under this
 * DID but keeps answering for what it signed earlier; removing the option is what retires the identity.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\Controllers\VerifiableCredentials\VciDidDocumentControllerTest
 */
class VciDidDocumentController
{
    /**
     * The representation type DID Core defines for a DID document in JSON-LD, which is what this is:
     * the document names the contexts its terms are defined by.
     */
    final public const string MEDIA_TYPE = 'application/did+ld+json';

    /**
     * How long a resolver may reuse the document without asking again.
     *
     * The document changes only when the signing keys do, and a key rollover is prepared by appending
     * the new pair well before it starts signing, so a cached copy an hour old still carries every key
     * anything has been signed with. Short enough that withdrawing a compromised key is not a day-long
     * wait.
     */
    protected const int CACHE_MAX_AGE_SECONDS = 3600;


    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        // Asked only for its local document factory, never for a built facade: this document is
        // assembled from key material already on disk, so it must not be able to fail on a cache
        // adapter or an outbound setting which exists to govern resolving other people's DIDs.
        protected readonly DidFactory $didFactory,
        protected readonly Routes $routes,
        protected readonly LoggerService $loggerService,
    ) {
    }


    public function didDocument(): Response
    {
        try {
            // The identifier alone, not the identity as a whole. Whether this document is published is
            // decided by this one option, and resolving the pair would also read and validate the issuer
            // identity mode - so a typo in a setting which has no bearing on this document would stop it
            // being served, and take every credential issued under the DID down with it.
            $didWeb = $this->moduleConfig->getVciIssuerDidIdentifier();
        } catch (Throwable $throwable) {
            $this->loggerService->error(
                'Unable to resolve the configured did:web identifier, so no DID document was served.',
                ['error' => $throwable->getMessage()],
            );

            return $this->routes->newResponse(null, Response::HTTP_INTERNAL_SERVER_ERROR, $this->baseHeaders());
        }

        if (is_null($didWeb)) {
            return $this->routes->newResponse(null, Response::HTTP_NOT_FOUND, $this->baseHeaders());
        }

        try {
            $didDocument = $this->didFactory->didDocumentFactory()->forDidWeb(
                new DidUrl($didWeb),
                // The whole key set rather than the pair which is currently signing. Every key which
                // has signed a credential still in circulation has to be here, or the credentials it
                // signed stop verifying the moment a newer pair is put in front of it; the same set is
                // published in JWKS, and for the same reason.
                $this->moduleConfig->getVciSignatureKeyPairBag(),
                // Only assertionMethod. These keys sign credentials and Status List Tokens and are used
                // for nothing else, and a relationship this deployment does not act in would be a claim
                // about the keys which is not true.
                [VerificationRelationshipEnum::AssertionMethod],
                // Stated rather than left to the library's default, so that a change to that default
                // can not silently alter the documents this module has already published.
                VerificationMethodTypeEnum::JsonWebKey2020,
            );
        } catch (Throwable $throwable) {
            // Fail closed. A document which does not describe the keys actually signing is worse than
            // no document: it would have a verifier reject valid credentials while reporting a key
            // mismatch rather than an outage.
            $this->loggerService->error(
                'Unable to build the DID document, so nothing was served.',
                ['didWeb' => $didWeb, 'error' => $throwable->getMessage()],
            );

            return $this->routes->newResponse(null, Response::HTTP_INTERNAL_SERVER_ERROR, $this->baseHeaders());
        }

        return $this->routes->newJsonResponse(
            $didDocument->jsonSerialize(),
            Response::HTTP_OK,
            $this->baseHeaders([
                'Content-Type' => self::MEDIA_TYPE,
                'Cache-Control' => 'public, max-age=' . self::CACHE_MAX_AGE_SECONDS,
            ]),
        );
    }


    /**
     * Headers every response from here carries.
     *
     * Cross origin reads are allowed on every outcome and not only on success, so that a browser based
     * wallet or verifier can tell a document which is not published from a network failure.
     *
     * @param array<string,string> $headers
     * @return array<string,string>
     */
    protected function baseHeaders(array $headers = []): array
    {
        return array_merge(['Access-Control-Allow-Origin' => '*'], $headers);
    }
}
