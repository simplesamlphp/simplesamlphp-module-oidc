<?php

namespace SimpleSAML\Module\oidc\Server\LogoutHandlers;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Pool;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use SimpleSAML\Logger;
use SimpleSAML\Module\oidc\Server\Associations\RelyingPartyAssociation;
use SimpleSAML\Module\oidc\Services\LogoutTokenBuilder;

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
        $client = new Client(['timeout' => 3]);

        $pool = new Pool($client, $this->logoutRequestsGenerator($relyingPartyAssociations), [
            'concurrency' => 5,
            'fulfilled' => function (Response $response, $index) {
                // this is delivered each successful response
                $successMessage = "Backhannel Logout (index $index) - success, status: {$response->getStatusCode()} " .
                    "{$response->getReasonPhrase()}";
                Logger::notice($successMessage);
            },
            'rejected' => function (GuzzleException $reason, $index) {
                // this is delivered each failed request
                $errorMessage = "Backhannel Logout (index $index) - error, reason: {$reason->getCode()} " .
                    "{$reason->getMessage()}, exception type: " . get_class($reason);
                Logger::error($errorMessage);
            },
        ]);

        try {
            $pool->promise()->wait();
        } catch (\Throwable $exception) {
            Logger::error('Backchannel Logout promise error: ' . $exception->getMessage());
        }
    }

    /**
     * @param array<string,RelyingPartyAssociation> $relyingPartyAssociations
     * @return \Generator
     */
    protected function logoutRequestsGenerator(array $relyingPartyAssociations): \Generator
    {
        $index = 0;
        foreach ($relyingPartyAssociations as $association) {
            if ($association->getBackchannelLogoutUri() !== null) {
                $logMessage = "Backhannel Logout (index $index) - preparing request to: " .
                    $association->getBackchannelLogoutUri();
                Logger::notice($logMessage);
                $index++;

                /** @psalm-suppress PossiblyNullArgument We have checked for nulls... */
                yield new Request(
                    'POST',
                    $association->getBackchannelLogoutUri(),
                    ['Content-Type' => 'application/x-www-form-urlencoded'],
                    http_build_query(
                        ['logout_token' => $this->logoutTokenBuilder->forRelyingPartyAssociation($association)]
                    )
                );
            }
        }
    }
}
