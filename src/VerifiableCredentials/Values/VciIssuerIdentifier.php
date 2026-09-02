<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\VerifiableCredentials\Values;

use SimpleSAML\Module\oidc\Codebooks\VciIssuerIdentifierModeEnum;
use SimpleSAML\Module\oidc\Exceptions\OidcException;

/**
 * What this deployment is configured to identify itself as when it issues a credential.
 *
 * Two options rather than one, so that neither has to be read as the other: the mode names which kind
 * of identity is issued under, and the did:web value is the identity itself. They are combined here so
 * that the rule tying them together is stated once, rather than at each of the several places which
 * ask what the issuer is called.
 *
 * The did:web value is deliberately kept even when the mode has moved on to something else. A
 * credential carries the identity it was issued with, and under did:web the only way to obtain the key
 * which signed it is to resolve that DID - so withdrawing the document the moment the mode changes
 * would make every credential issued under it permanently unverifiable. Keeping the option set says
 * "no longer issue under this, but keep publishing it"; removing it is what retires the identity, and
 * is then an explicit act rather than a side effect of switching mode.
 */
class VciIssuerIdentifier
{
    /**
     * @param \SimpleSAML\Module\oidc\Codebooks\VciIssuerIdentifierModeEnum $mode Which identity newly
     * issued credentials are signed under.
     * @param ?string $didWeb The configured did:web, whatever the mode is, or null when none is
     * configured. Already validated as one this library could resolve.
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     */
    public function __construct(
        protected readonly VciIssuerIdentifierModeEnum $mode,
        protected readonly ?string $didWeb = null,
    ) {
        // Configuration catches this with the option names in hand, so reaching it here means a caller
        // built the pair directly. Refused all the same: the alternative is issuing credentials whose
        // `iss` is an empty string.
        if ($this->mode === VciIssuerIdentifierModeEnum::DidWeb && is_null($this->didWeb)) {
            throw new OidcException(
                sprintf(
                    'Issuer identifier mode "%s" needs the did:web identifier to issue under, and none ' .
                    'is set.',
                    VciIssuerIdentifierModeEnum::DidWeb->value,
                ),
            );
        }
    }


    public function getMode(): VciIssuerIdentifierModeEnum
    {
        return $this->mode;
    }


    /**
     * The configured did:web, which is published whenever it is set - see the class note for why that
     * is not conditioned on the mode.
     *
     * @see \SimpleSAML\Module\oidc\ModuleConfig::OPTION_VCI_ISSUER_DID_IDENTIFIER
     */
    public function getDidWeb(): ?string
    {
        return $this->didWeb;
    }


    /**
     * Whether newly issued credentials are issued under the did:web identity.
     *
     * Distinct from having one configured: a deployment which has moved on to another mode still
     * publishes its document, but no longer signs anything under it.
     */
    public function isIssuingUnderDidWeb(): bool
    {
        return $this->mode === VciIssuerIdentifierModeEnum::DidWeb;
    }
}
