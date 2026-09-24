<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\ValueAbstracts;

use SimpleSAML\Module\oidc\Exceptions\OidcException;

/**
 * Which issuers' tokens a resource server may have introspected upstream on its behalf: an allow list or a deny
 * list, kept on the resource server's client record, and the only per-caller restriction on tokens this OP did
 * not issue.
 *
 * Asked twice. Before a token is sent anywhere, about the issuer read out of the presented token without
 * verifying it: refusing on a claim nobody verified is safe, since whoever forged it can only refuse themselves,
 * and it keeps a refused issuer's tokens away from the upstream. And again about the issuer the upstream answer
 * names, since only that one can be relied on to permit anything.
 */
class ForeignIssuerList
{
    final public const string KEY_ALLOW = 'allow';

    final public const string KEY_DENY = 'deny';


    /**
     * @param string[] $issuers
     */
    protected function __construct(
        protected readonly bool $isAllowList,
        protected readonly array $issuers,
    ) {
    }


    /**
     * @param string[] $issuers The only issuers permitted; none at all, when empty.
     */
    public static function allow(array $issuers): self
    {
        return new self(true, array_values($issuers));
    }


    /**
     * @param string[] $issuers The issuers refused; every other one is permitted.
     */
    public static function deny(array $issuers): self
    {
        return new self(false, array_values($issuers));
    }


    /**
     * The list as a client record keeps it: `['allow' => [issuers]]` or `['deny' => [issuers]]`, or null for a
     * resource server which has none.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException When the stored value is neither. It is never
     * read as "no list", which would lift a restriction somebody put there.
     */
    public static function fromClientMetadata(mixed $value): ?self
    {
        if (is_null($value)) {
            return null;
        }

        if (
            !is_array($value) ||
            count($value) !== 1 ||
            !in_array(array_key_first($value), [self::KEY_ALLOW, self::KEY_DENY], true)
        ) {
            throw new OidcException(
                'The foreign issuer list must be either [\'allow\' => [issuers]] or [\'deny\' => [issuers]].',
            );
        }

        $issuers = reset($value);

        if (!is_array($issuers) || !array_is_list($issuers)) {
            throw new OidcException('The issuers of the foreign issuer list must be a list.');
        }

        foreach ($issuers as $issuer) {
            if (!is_string($issuer) || $issuer === '') {
                throw new OidcException('Every issuer of the foreign issuer list must be a non-empty string.');
            }
        }

        /** @var string[] $issuers */
        return array_key_first($value) === self::KEY_ALLOW ? self::allow($issuers) : self::deny($issuers);
    }


    /**
     * Issuers are compared exactly, without normalisation, as an issuer identifier is where metadata is
     * checked against it (RFC 8414 section 3.3: "MUST be identical").
     */
    public function permits(string $issuer): bool
    {
        return in_array($issuer, $this->issuers, true) === $this->isAllowList;
    }


    public function isAllowList(): bool
    {
        return $this->isAllowList;
    }


    /**
     * @return string[]
     */
    public function getIssuers(): array
    {
        return $this->issuers;
    }
}
