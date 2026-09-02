<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers;

use SimpleSAML\Module\oidc\Codebooks\StatusListKeyProfileEnum;
use SimpleSAML\Module\oidc\Codebooks\VciIssuerIdentifierModeEnum;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\Jwks;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

class JwksController
{
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly Jwks $jwks,
        protected readonly Routes $routes,
    ) {
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function __invoke(): JsonResponse
    {
        $federationPublicKeys = $this->moduleConfig->getFederationEnabled()
        ? $this->moduleConfig->getFederationSignatureKeyPairBag()->getAllPublicKeys()
        : [];

        // Published while Verifiable Credential Issuance is on, and also while any Status List pool is
        // configured to identify its signing key through this key set. Status Lists outlive the switch
        // which stops new credentials being issued -- credentials already in wallets point at those
        // lists and have to stay verifiable -- so withdrawing the key their tokens are signed with the
        // moment issuance is turned off would break exactly the guarantee that lifecycle rests on.
        //
        // The issuer identity mode is asked for the same reason. Under it, a credential names its
        // signing key by the identifier it carries here and nowhere else, so a credential already in a
        // wallet is verifiable only while this key set still lists that key.
        $isVciKeySetNeeded = $this->moduleConfig->getVciEnabled() ||
        $this->isAnyStatusListKeyPublished() ||
        $this->isCredentialKeyResolvedThroughThisKeySet();

        $vciPublicKeys = $isVciKeySetNeeded
        ? $this->moduleConfig->getVciSignatureKeyPairBag()->getAllPublicKeys()
        : [];

        return $this->routes->newJsonResponse(
            $this->jwks->jwksDecoratorFactory()->fromJwkDecorators(
                ...$this->moduleConfig->getProtocolSignatureKeyPairBag()->getAllPublicKeys(),
                ...$federationPublicKeys,
                ...$vciPublicKeys,
            )->jsonSerialize(),
        );
    }


    /**
     * Whether any configured Status List pool expects its tokens to be verified through this key set.
     *
     * Answered from configuration alone, deliberately. Asking the stored lists instead would be more
     * precise -- a list outlives the pool which created it, so a pool removed or moved to the other key
     * profile leaves lists behind which still need this key. But answering it would mean this endpoint
     * holding a repository, and resolving that dependency opens a database connection before the
     * controller is even entered. A key set which has never needed a database would then fail whenever
     * the database did, taking down verification of every ID token and access token this issuer has
     * ever signed. That is a far larger failure than the one it would prevent.
     *
     * The gap this leaves is an operator removing a pool, or switching it to the other key profile,
     * while lists created under the old one are still being served. That is the same class of change as
     * removing the signing key itself, and it is caught where it can be acted on: publication resolves
     * a list's key by the ID stored on it and fails closed rather than signing with something else.
     */
    protected function isAnyStatusListKeyPublished(): bool
    {
        try {
            foreach ($this->moduleConfig->getVciStatusListPoolBag()->getAll() as $pool) {
                if ($pool->getKeyProfile() === StatusListKeyProfileEnum::Jwks) {
                    return true;
                }
            }
        } catch (Throwable) {
            // A pool which can not be resolved is reported on the configuration overview screen, which
            // owns that error. Here the conservative reading is that no pool needs its key published,
            // which leaves the key set exactly as it was before Status Lists existed.
            return false;
        }

        return false;
    }


    /**
     * Whether credentials this deployment issues name their signing key by its identifier in this key
     * set, rather than carrying the key with them.
     *
     * Answered from configuration alone, for the same reason the Status List question above is: a
     * repository would open a database connection before this controller is entered, and a key set
     * which has never needed a database would then fail whenever the database did, taking down
     * verification of every token this issuer has ever signed.
     *
     * The gap that leaves is an operator moving the issuer identity off this mode while credentials
     * issued under it are still being verified. That is reported where it can be acted on: the
     * Verifiable Credential configuration screen lists the identities credentials were actually issued
     * under, which is a question configuration cannot answer.
     */
    protected function isCredentialKeyResolvedThroughThisKeySet(): bool
    {
        try {
            return $this->moduleConfig->getVciIssuerIdentifierMode() === VciIssuerIdentifierModeEnum::Https;
        } catch (Throwable) {
            // A mode which cannot be resolved is reported on the configuration overview screen, which
            // owns that error. Here the conservative reading is the one which leaves this key set as it
            // was before the issuer identity was configurable at all.
            return false;
        }
    }


    public function jwks(): Response
    {
        $response = $this->__invoke();
        $response->headers->set('Access-Control-Allow-Origin', '*');
        return $response;
    }
}
