<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Services;

use SimpleSAML\Module\oidc\Codebooks\VciIssuerIdentifierModeEnum;
use SimpleSAML\Module\oidc\Exceptions\OidcException;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\VciIssuerIdentifier;
use SimpleSAML\Module\oidc\VerifiableCredentials\VciIssuerIdentityResolver;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Jwk;
use SimpleSAML\OpenID\Jwks;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPair;

/**
 * The `vc_issuer` metadata of the Entity Configuration: the keys this deployment signs Digital
 * Credentials with.
 *
 * OpenID Fed DCP (Appendix B of DIIP v5) has a Credential Issuer publish those keys as a JWK Set in the
 * `jwks` of this Entity Type, distinct from the Federation Entity Keys in the statement's own `jwks`
 * claim, which sign the statement. A verifier establishes trust in a credential by resolving the
 * Issuer's Trust Chain from its Entity Configuration and then requiring that the credential's `kid`
 * header names a key in this set.
 *
 * That last step is why each key is published under every identifier a credential may carry for it,
 * and not only under its bare key id. Which identifier a credential carries depends on the issuer
 * identity mode it was issued under: a DID URL under `did:jwk` and `did:web`, the bare id under
 * `https`. The mode a deployment issues under today is asked of the same resolver which names the key
 * at signing time, so that the `kid` a verifier reads from a credential and the one it looks for here
 * can not be built under different rules. The modes it may have issued under before are published
 * beside it, for as long as each remains something a credential could still be verified against: the
 * bare id and the did:jwk URL, since neither needs anything configured, and the did:web URL for as
 * long as a did:web is configured - which is also exactly as long as its DID document stays published
 * for the credentials issued under it. A verifier finds the same key under whichever name its
 * credential uses.
 *
 * Every configured pair is published, not only the one signing now, for the same reason every one of
 * them is in the key set at the JWKS endpoint: a credential signed under a pair which has since been
 * rotated out of the signing seat has to stay verifiable for as long as it is valid. And it is
 * published whether or not issuance is switched on, for the same reason again: a credential in a
 * wallet outlives the switch. What retains the keys is that they stay configured, which is what the
 * installation guide asks of a deployment that turns issuance off - so this reads the configuration
 * and nothing else, and a deployment which never set the keys up has nothing here to publish.
 *
 * Built on the first request for it, like CredentialIssuerMetadataService and for the same reason: the
 * Entity Configuration is wired to this for deployments which have no credential keys at all, and
 * asking is what reads the settings.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\Services\VcIssuerMetadataServiceTest
 */
class VcIssuerMetadataService
{
    /**
     * @var ?array<string,mixed>
     */
    protected ?array $metadata = null;


    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly Jwk $jwk,
        protected readonly Jwks $jwks,
        protected readonly VciIssuerIdentityResolver $vciIssuerIdentityResolver,
    ) {
    }


    /**
     * @return array<string,mixed>
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     * @throws \SimpleSAML\OpenID\Exceptions\OpenIdException
     */
    public function getMetadata(): array
    {
        return $this->metadata ??= $this->buildMetadata();
    }


    /**
     * @return array<string,mixed>
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     * @throws \SimpleSAML\OpenID\Exceptions\OpenIdException
     */
    protected function buildMetadata(): array
    {
        $issuerIdentifier = $this->moduleConfig->getVciIssuerIdentifier();

        // A list rather than the bag's keyed array, since it is spread into a variadic below.
        $jwkDecorators = [];

        foreach ($this->moduleConfig->getVciSignatureKeyPairBag()->getAll() as $signatureKeyPair) {
            $publicJwk = $signatureKeyPair->getKeyPair()->getPublicKey()->jsonSerialize();

            foreach ($this->keyIdsFor($signatureKeyPair, $issuerIdentifier) as $keyId) {
                $jwkDecorators[] = $this->jwk->jwkDecoratorFactory()->fromData([
                    ...$publicJwk,
                    ClaimsEnum::Kid->value => $keyId,
                ]);
            }
        }

        return [
            ClaimsEnum::Jwks->value => $this->jwks->jwksDecoratorFactory()
                ->fromJwkDecorators(...$jwkDecorators)
                ->jsonSerialize(),
        ];
    }


    /**
     * Every identifier a credential signed with this pair may name it by: the one in use today first,
     * then one for each other identity mode this deployment could have issued under.
     *
     * The name in use today is resolved exactly as it is at signing time, and a failure there is a
     * failure to publish. The others are best effort: an alias the resolver can not derive now - a key
     * too large to fit in a did:jwk, say - could not have been derived when a credential was issued
     * under it either, so no credential carries it and nothing is lost by leaving it out. Only the
     * resolver's own refusal is read that way; anything else is a fault and stays one.
     *
     * @return list<string>
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     */
    protected function keyIdsFor(SignatureKeyPair $signatureKeyPair, VciIssuerIdentifier $issuerIdentifier): array
    {
        $keyIds = [$this->vciIssuerIdentityResolver->resolve($issuerIdentifier, $signatureKeyPair)->getKeyId()];

        foreach (VciIssuerIdentifierModeEnum::cases() as $mode) {
            if ($mode === $issuerIdentifier->getMode()) {
                continue;
            }

            try {
                $alias = $this->aliasUnder($mode, $signatureKeyPair, $issuerIdentifier->getDidWeb());
            } catch (OidcException) {
                continue;
            }

            if ($alias !== null) {
                $keyIds[] = $alias;
            }
        }

        return array_values(array_unique($keyIds));
    }


    /**
     * What a credential issued under another identity mode would have named this pair's key by, or null
     * where that mode has nothing to name it by.
     *
     * The bare key id is the pair's own and needs no resolving; it is what the `https` identity names
     * the key by, and asking the resolver for it would also assert that the issuer URL is discoverable,
     * which is that mode's concern and not an alias's. The did:jwk URL is derived from the key alone.
     * The did:web URL exists only while a did:web is configured, under whichever mode - which is also
     * exactly as long as its DID document stays published for the credentials issued under it.
     *
     * A mode added later has to say here what it names a key by, rather than being published under
     * nothing by falling through.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     */
    protected function aliasUnder(
        VciIssuerIdentifierModeEnum $mode,
        SignatureKeyPair $signatureKeyPair,
        ?string $didWeb,
    ): ?string {
        return match ($mode) {
            VciIssuerIdentifierModeEnum::Https => $signatureKeyPair->getKeyPair()->getKeyId(),
            VciIssuerIdentifierModeEnum::DidJwk => $this->vciIssuerIdentityResolver->resolve(
                new VciIssuerIdentifier(VciIssuerIdentifierModeEnum::DidJwk),
                $signatureKeyPair,
            )->getKeyId(),
            VciIssuerIdentifierModeEnum::DidWeb => $didWeb === null ? null : $this->vciIssuerIdentityResolver->resolve(
                new VciIssuerIdentifier(VciIssuerIdentifierModeEnum::DidWeb, $didWeb),
                $signatureKeyPair,
            )->getKeyId(),
        };
    }
}
