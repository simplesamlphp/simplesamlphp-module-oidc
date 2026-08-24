<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\LogoutHandlers;

use Generator;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\StreamHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Pool;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\RequestOptions;
use GuzzleHttp\Utils;
use SimpleSAML\Module\oidc\Factories\DestinationPolicyFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Services\LogoutTokenBuilder;
use SimpleSAML\OpenID\Network\AddressPinner;
use SimpleSAML\OpenID\Network\DestinationPolicy;
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

    /**
     * Name the destination guard is pushed under, so a stack that outlives one logout carries one guard
     * rather than gaining another with every call.
     */
    protected const string DESTINATION_GUARD_NAME = 'oidc_destination_guard';

    /**
     * Options with which Guzzle picks its handler on more than this system's capabilities, so its choice
     * cannot be established here. Mirrors what the openid library checks before claiming a pin.
     *
     * @var list<string>
     */
    protected const array HANDLER_SELECTION_OPTIONS = [
        'max_host_connections',
        'max_total_connections',
        'transport_sharing',
        'multiplex',
    ];


    public function __construct(
        protected LogoutTokenBuilder $logoutTokenBuilder = new LogoutTokenBuilder(),
        protected LoggerService $loggerService = new LoggerService(),
        protected ModuleConfig $moduleConfig = new ModuleConfig(),
        protected ?DestinationPolicy $destinationPolicy = null,
    ) {
    }


    /**
     * A logout URI is registered by the client, so it names a destination the deployment did not choose,
     * exactly like a `jwks_uri` does. This client is built here rather than by the openid library, so the
     * guard has to be attached by hand instead of arriving with the client.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\OpenID\Exceptions\DestinationPolicyException
     * @throws \Exception
     */
    protected function destinationPolicy(): DestinationPolicy
    {
        return $this->destinationPolicy ??= (new DestinationPolicyFactory(
            $this->moduleConfig,
            $this->loggerService,
        ))->build();
    }


    /**
     * Attach the destination guard to the client, and return the client that carries it.
     *
     * Done after construction rather than by handing Guzzle a handler, so that its own derivation of the
     * handler from the client configuration is left intact: replacing the handler outright would discard a
     * handler a deployment configured, and would stop handler-selection options (connection caps, transport
     * sharing, multiplexing) from reaching the choice Guzzle makes.
     *
     * @param array<string,mixed> $clientConfig
     * @param bool $hasSuppliedTransport Whether the transport came from outside this method, in which case
     *        nothing can be established about it.
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\OpenID\Exceptions\DestinationPolicyException
     * @throws \Exception
     */
    protected function guarded(Client $client, array $clientConfig, bool $hasSuppliedTransport): Client
    {
        $middleware = $this->destinationPolicy()->middleware(
            // A transport supplied from outside says nothing about itself, and claiming a pin that the
            // transport ignores would be a guarantee that was never made.
            new AddressPinner($hasSuppliedTransport ? false : $this->isCurlHandlerAvailable($clientConfig)),
        );

        // Reading configuration back off a client is deprecated in Guzzle, but it is the only way to reach
        // the handler it derived for itself.
        /** @psalm-suppress MixedAssignment */
        $handler = $client->getConfig('handler');

        if ($handler instanceof HandlerStack) {
            // A stack that came from configuration outlives this call, so a guard from a previous logout is
            // still on it. Removing before pushing keeps one guard rather than another per logout, which
            // would otherwise repeat the policy check and its DNS lookup once more each time.
            $handler->remove(self::DESTINATION_GUARD_NAME);

            // push() puts this at the end of the stack, which Guzzle applies in reverse, so it sits below
            // the redirect middleware and runs again for every hop rather than only for the original
            // request. The middleware declares the request and response types it actually handles, which is
            // narrower than the bare callable(callable):callable that push() is typed for.
            /** @psalm-suppress MixedArgumentTypeCoercion */
            $handler->push($middleware, self::DESTINATION_GUARD_NAME);

            return $client;
        }

        if (is_callable($handler)) {
            // A bare callable handler cannot be pushed onto, so wrap it instead of leaving the requests
            // through it unguarded. There is no redirect middleware in this case, so there is no chain for
            // the guard to sit below.
            // A handler read back off the client is only known to be callable; that it takes a request and
            // options and returns a promise is Guzzle's own contract for one.
            /** @psalm-suppress MixedArgumentTypeCoercion */
            $clientConfig['handler'] = $middleware($handler);

            return new Client($clientConfig);
        }

        $this->loggerService->warning(
            'The outbound destination policy could not be attached to the Back-Channel Logout HTTP client, ' .
            'because its handler is neither a handler stack nor callable. Logout requests are not ' .
            'restricted to permitted destinations.',
        );

        return $client;
    }


    /**
     * Whether Guzzle's own handler for this system is a cURL one, which is what decides whether an address
     * can be pinned. Asked of Guzzle rather than inferred from the extension being loaded, since the cURL
     * functions can be disabled or libcurl built without the SSL support Guzzle requires, in which case it
     * quietly selects the stream handler, which ignores a cURL option.
     *
     * @param array<string,mixed> $clientConfig
     */
    protected function isCurlHandlerAvailable(array $clientConfig): bool
    {
        foreach (self::HANDLER_SELECTION_OPTIONS as $option) {
            if (array_key_exists($option, $clientConfig)) {
                return false;
            }
        }

        try {
            return !Utils::chooseHandler() instanceof StreamHandler;
        } catch (Throwable) {
            return false;
        }
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

        // Whether the transport was decided anywhere but here: by a test, or by a deployment configuring
        // its own handler. Either way nothing can be established about what it honours.
        //
        // isset() rather than array_key_exists(), to match how Guzzle reads this: it treats an explicit
        // null as no handler at all and builds its normal stack, which can pin. Counting that as a
        // supplied transport would give up pinning for a client that never had one.
        $hasSuppliedTransport = isset($clientConfig['handler']);

        // Guarded whatever its origin, so the stack a test supplies goes through the same middleware as the
        // one Guzzle builds. A guard present only on the untested path is how one quietly stops existing.
        $client = $this->guarded(new Client($clientConfig), $clientConfig, $hasSuppliedTransport);

        $pool = new Pool($client, $this->logoutRequestsGenerator($relyingPartyAssociations), [
            'concurrency' => 5,
            'fulfilled' => function (Response $response, mixed $index) {
                // this is delivered each successful response
                $successMessage = "Backchannel Logout (index $index) - success, status: {$response->getStatusCode()} " .
                    "{$response->getReasonPhrase()}";
                $this->loggerService->notice($successMessage);
            },
            // Typed Throwable rather than GuzzleException: a request can be rejected by something that is
            // not a transport failure at all, notably the outbound destination policy refusing the logout
            // URI. Narrowing this to GuzzleException made such a rejection miss the per-request report and
            // surface through the catch below, without the index naming which client it was.
            'rejected' => function (Throwable $reason, mixed $index) {
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
