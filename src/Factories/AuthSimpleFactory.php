<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories;

use League\OAuth2\Server\Entities\ClientEntityInterface as OAuth2ClientEntityInterface;
use SimpleSAML\Auth\Simple;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\ModuleConfig;

class AuthSimpleFactory
{
    public function __construct(
        private readonly ModuleConfig $moduleConfig,
    ) {
    }


    /**
     * @codeCoverageIgnore
     * @throws \Exception
     */
    public function build(OAuth2ClientEntityInterface $clientEntity): Simple
    {
        $authSourceId = $this->resolveAuthSourceId($clientEntity);

        return new Simple($authSourceId);
    }


    /**
     * @return \SimpleSAML\Auth\Simple The default authsource
     * @throws \Exception
     */
    public function getDefaultAuthSource(): Simple
    {
        return new Simple($this->moduleConfig->getDefaultAuthSourceId());
    }


    /**
     * Get auth source defined on the client. If not set on the client, get the default auth source defined in config.
     *
     * @throws \Exception
     */
    public function resolveAuthSourceId(OAuth2ClientEntityInterface $client): string
    {
        // Only this module's own client entity carries an authentication source; a plain OAuth2 client
        // has nowhere to state one, so it authenticates against the configured default.
        if ($client instanceof ClientEntityInterface) {
            return $client->getAuthSourceId() ?? $this->moduleConfig->getDefaultAuthSourceId();
        }

        return $this->moduleConfig->getDefaultAuthSourceId();
    }


    public function forAuthSourceId(string $authSourceId): Simple
    {
        return new Simple($authSourceId);
    }
}
