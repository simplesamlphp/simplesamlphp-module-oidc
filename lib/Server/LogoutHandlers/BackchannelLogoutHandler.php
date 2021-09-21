<?php

namespace SimpleSAML\Module\oidc\Server\LogoutHandlers;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Pool;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use SimpleSAML\Logger;
use SimpleSAML\Module\oidc\Server\Associations\RelyingPartyAssociation;

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

        /** Array with URI as key body as value */
        $requestsData = [];
        foreach ($backchannelLogoutEnabledRelyingPartyAssociations as $association) {
            /** @psalm-suppress PossiblyNullArrayOffset We have filtered out associations with no BCL URI */
            $requestsData[$association->getBackchannelLogoutUri()] =
                http_build_query(
                    ['logout_token' => $this->logoutTokenBuilder->forRelyingPartyAssociation($association)]
                );
        }

        $client = new Client(['timeout' => 5]);

        $pool = new Pool($client, $this->logoutRequestsGenerator($requestsData), [
            'concurrency' => 5,
            'fulfilled' => function (Response $response, $index) {
                // this is delivered each successful response
                // TODO Log this
            },
            'rejected' => function (RequestException $reason, $index) {
                // this is delivered each failed request
                // TODO log this
            },
        ]);

        $pool->promise()->wait();
    }

    protected function logoutRequestsGenerator(array $requestsData): \Generator
    {
        foreach ($requestsData as $uri => $body) {
            yield new Request(
                'POST',
                $uri,
                ['Content-Type' => 'application/x-www-form-urlencoded'],
                $body
            );
        }
    }
}
