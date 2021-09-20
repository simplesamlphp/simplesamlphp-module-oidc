<?php

namespace SimpleSAML\Module\oidc\Server\LogoutHandlers;

use SimpleSAML\Module\oidc\Server\Associations\RelyingPartyAssociation;
use SimpleSAML\Module\oidc\Services\ConfigurationService;

class BackchannelLogoutHandler
{
    protected LogoutTokenBuilder $logoutTokenBuilder;

    public function __construct(
        ?LogoutTokenBuilder $logoutTokenBuilder = null
    ) {
        $this->logoutTokenBuilder = $logoutTokenBuilder ?? new LogoutTokenBuilder();
    }

    /**
     * @param array<string,RelyingPartyAssociation> $relyingPartyAssociations
     */
    public function handle(array $relyingPartyAssociations): void
    {
        $backchannelLogoutEnabledRelyingPartyAssociations = array_filter(
            $relyingPartyAssociations,
            fn($association) => $association->getBackchannelLogoutUri() !== null
        );

        if (empty($backchannelLogoutEnabledRelyingPartyAssociations)) {
            return;
        }

        $logoutUriToLogoutTokenMap = [];

        foreach ($backchannelLogoutEnabledRelyingPartyAssociations as $association) {
            /** @psalm-suppress PossiblyNullArrayOffset We have filtered out associations with no BCL URI */
            $logoutUriToLogoutTokenMap[$association->getBackchannelLogoutUri()] =
                $this->logoutTokenBuilder->forRelyingPartyAssociation($association);
        }

        // TODO prepare and send requests
    }
}
