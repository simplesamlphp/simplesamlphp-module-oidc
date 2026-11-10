<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\ValueAbstracts;

use SimpleSAML\Module\oidc\ModuleConfig;

/**
 * Which credential configurations an API caller may act on at the Verifiable Credential endpoints: offer them,
 * and change the status of the credentials issued from them.
 *
 * A token's scopes say which endpoints it may call; this says which credentials. A logged in SimpleSAMLphp
 * administrator is not limited. An API token is limited to the credential configurations it is configured with
 * ({@see \SimpleSAML\Module\oidc\ModuleConfig::getApiTokenCredentialConfigurationIds()}), which are none at all
 * when it is configured with no list.
 *
 * No limit, not even no limit at all, allows a credential whose configuration is not known: it can not be said
 * to be one of all the configurations. Only a change made without a limit, from the administration screens, acts
 * on such a credential.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\ValueAbstracts\CredentialConfigurationLimitTest
 */
class CredentialConfigurationLimit
{
    /**
     * @param ?string[] $credentialConfigurationIds Null for no limit.
     */
    protected function __construct(
        protected readonly ?array $credentialConfigurationIds,
    ) {
    }


    public static function unlimited(): self
    {
        return new self(null);
    }


    /**
     * @param string[] $credentialConfigurationIds None allows nothing.
     */
    public static function to(array $credentialConfigurationIds): self
    {
        return new self(array_values(array_unique($credentialConfigurationIds)));
    }


    /**
     * The limit an API token's configured list sets: no list allows none, and a list holding the wildcard alone
     * allows all.
     *
     * The wildcard beside IDs is refused when the configuration is read. Should it get here anyway, it is taken
     * as an ID like any other, which no credential configuration has, so the limit is the IDs beside it and never
     * all of them.
     *
     * @param ?string[] $configuredIds As {@see ModuleConfig::getApiTokenCredentialConfigurationIds()} returns them.
     */
    public static function fromConfiguredIds(?array $configuredIds): self
    {
        if ($configuredIds === [ModuleConfig::API_TOKEN_ALL_CREDENTIAL_CONFIGURATIONS]) {
            return self::unlimited();
        }

        return self::to($configuredIds ?? []);
    }


    public function isUnlimited(): bool
    {
        return $this->credentialConfigurationIds === null;
    }


    /**
     * @param ?string $credentialConfigurationId Null where it is not known, which no limit allows.
     */
    public function allows(?string $credentialConfigurationId): bool
    {
        if ($credentialConfigurationId === null) {
            return false;
        }

        return $this->credentialConfigurationIds === null ||
        in_array($credentialConfigurationId, $this->credentialConfigurationIds, true);
    }


    /**
     * @return ?string[] Null when there is no limit.
     */
    public function getCredentialConfigurationIds(): ?array
    {
        return $this->credentialConfigurationIds;
    }
}
