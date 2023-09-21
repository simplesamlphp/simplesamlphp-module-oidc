<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\LogoutHandlers;

use Generator;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Pool;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use League\OAuth2\Server\Exception\OAuthServerException;
use SimpleSAML\Module\oidc\Server\Associations\Interfaces\RelyingPartyAssociationInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Services\LogoutTokenBuilder;
use Throwable;

class BackChannelLogoutHandler
{
    protected LogoutTokenBuilder $logoutTokenBuilder;

    protected LoggerService $loggerService;

    public function __construct(
        ?LogoutTokenBuilder $logoutTokenBuilder = null,
        ?LoggerService $loggerService = null
    ) {
        $this->logoutTokenBuilder = $logoutTokenBuilder ?? new LogoutTokenBuilder();
        $this->loggerService = $loggerService ?? new LoggerService();
    }

    /**
     * @param array<RelyingPartyAssociationInterface> $relyingPartyAssociations
     * @param HandlerStack|null $handlerStack For easier testing
     * @throws OAuthServerException
     */
    public function handle(array $relyingPartyAssociations, HandlerStack $handlerStack = null): void
    {
        $clientConfig = ['timeout' => 3, 'verify' => false, 'handler' => $handlerStack];

        $client = new Client($clientConfig);

        $pool = new Pool($client, $this->logoutRequestsGenerator($relyingPartyAssociations), [
            'concurrency' => 5,
            'fulfilled' => function (Response $response, mixed $index) {
                // this is delivered each successful response
                $successMessage = "Backhannel Logout (index $index) - success, status: {$response->getStatusCode()} " .
                    "{$response->getReasonPhrase()}";
                $this->loggerService->notice($successMessage);
            },
            'rejected' => function (GuzzleException $reason, mixed $index) {
                // this is delivered each failed request
                $errorMessage = "Backhannel Logout (index $index) - error, reason: {$reason->getCode()} " .
                    "{$reason->getMessage()}, exception type: " . $reason::class;
                $this->loggerService->error($errorMessage);
            },
        ]);

        try {
            $pool->promise()->wait();
        } catch (Throwable $exception) {
            $this->loggerService->error('Back-channel Logout promise error: ' . $exception->getMessage());
        }
    }

    /**
     * @param array<RelyingPartyAssociationInterface> $relyingPartyAssociations
     * @return Generator
     * @throws OAuthServerException
     */
    protected function logoutRequestsGenerator(array $relyingPartyAssociations): Generator
    {
        $index = 0;
        foreach ($relyingPartyAssociations as $association) {
            if ($association->getBackChannelLogoutUri() !== null) {
                $logMessage = "Backhannel Logout (index $index) - preparing request to: " .
                    ($association->getBackChannelLogoutUri() ?? '');
                $this->loggerService->notice($logMessage);
                $index++;

                $query = http_build_query(
                    ['logout_token' => $this->logoutTokenBuilder->forRelyingPartyAssociation($association)]
                );

                /** @psalm-suppress PossiblyNullArgument We have checked for nulls... */
                yield new Request(
                    'POST',
                    $association->getBackChannelLogoutUri(),
                    ['Content-Type' => 'application/x-www-form-urlencoded'],
                    $query
                );
            }
        }
    }
}
