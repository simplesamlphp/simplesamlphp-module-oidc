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
use GuzzleHttp\RequestOptions;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Services\LogoutTokenBuilder;
use Throwable;

class BackChannelLogoutHandler
{
    /**
     * Baseline Guzzle options for the outbound Back-Channel Logout requests. Deployment-specific options from
     * ModuleConfig::getBackChannelLogoutHttpClientOptions() are merged over these, so a deployment can override
     * any of them. Note that TLS verification is deliberately absent here: Guzzle verifies by default, and the
     * Logout Token carries the `sub` / `sid` claims, so it must not be sent over an unverified connection
     * unless a deployment explicitly opts out.
     *
     * @var array<string,mixed>
     */
    protected const array DEFAULT_HTTP_CLIENT_OPTIONS = [
        RequestOptions::CONNECT_TIMEOUT => 3,
        RequestOptions::TIMEOUT => 3,
    ];

    public function __construct(
        protected LogoutTokenBuilder $logoutTokenBuilder = new LogoutTokenBuilder(),
        protected LoggerService $loggerService = new LoggerService(),
        protected ModuleConfig $moduleConfig = new ModuleConfig(),
    ) {
    }

    /**
     * @param \SimpleSAML\Module\oidc\Server\Associations\Interfaces\RelyingPartyAssociationInterface[]
     *   $relyingPartyAssociations
     * @param \GuzzleHttp\HandlerStack|null $handlerStack For easier testing
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \Exception
     */
    public function handle(array $relyingPartyAssociations, ?HandlerStack $handlerStack = null): void
    {
        $clientConfig = array_merge(
            self::DEFAULT_HTTP_CLIENT_OPTIONS,
            $this->moduleConfig->getBackChannelLogoutHttpClientOptions(),
        );

        if ($handlerStack instanceof HandlerStack) {
            $clientConfig['handler'] = $handlerStack;
        }

        $client = new Client($clientConfig);

        $pool = new Pool($client, $this->logoutRequestsGenerator($relyingPartyAssociations), [
            'concurrency' => 5,
            'fulfilled' => function (Response $response, mixed $index) {
                // this is delivered each successful response
                $successMessage = "Backchannel Logout (index $index) - success, status: {$response->getStatusCode()} " .
                    "{$response->getReasonPhrase()}";
                $this->loggerService->notice($successMessage);
            },
            'rejected' => function (GuzzleException $reason, mixed $index) {
                // this is delivered each failed request
                $errorMessage = "Backchannel Logout (index $index) - error, reason: {$reason->getCode()} " .
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
     * @param \SimpleSAML\Module\oidc\Server\Associations\Interfaces\RelyingPartyAssociationInterface[]
     *   $relyingPartyAssociations
     * @return \Generator
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
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
                    ['logout_token' => $this->logoutTokenBuilder->forRelyingPartyAssociation($association)],
                );

                /** @psalm-suppress PossiblyNullArgument We have checked for nulls... */
                yield new Request(
                    'POST',
                    $association->getBackChannelLogoutUri(),
                    ['Content-Type' => 'application/x-www-form-urlencoded'],
                    $query,
                );
            }
        }
    }
}
