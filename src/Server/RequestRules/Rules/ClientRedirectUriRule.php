<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use LogicException;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\ApplicationTypesEnum;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;
use Throwable;

/**
 * @extends \SimpleSAML\Module\oidc\Server\RequestRules\Rules\AbstractRule<string>
 */
class ClientRedirectUriRule extends AbstractRule
{
    /**
     * A loopback redirect URI, RFC 8252 section 7.3: "http://127.0.0.1:{port}/{path}" for IPv4, and
     * "http://[::1]:{port}/{path}" for IPv6. Matched on the URI as written: the scheme, the address right after it (no
     * userinfo), a port or none, then a path, query or fragment without a backslash, a space or a control character,
     * or nothing. Strict, because a browser reads the URI by the WHATWG URL Standard rather than as PHP's parse_url()
     * does: parse_url() takes "http://evil.example\@127.0.0.1/" for a URI of the host 127.0.0.1, which a browser,
     * reading the backslash as a slash, sends to evil.example. Not `localhost`, which section 8.3 does not recommend,
     * since a name may resolve elsewhere.
     */
    protected const string LOOPBACK_REDIRECT_URI_PATTERN =
    '~^http://(?:127\.0\.0\.1|\[::1\])(?::[0-9]+)?(?:[/?#][^\\\\\x00-\x20\x7F]*)?\z~i';


    public function __construct(
        RequestParamsResolver $requestParamsResolver,
        Helpers $helpers,
        protected ModuleConfig $moduleConfig,
    ) {
        parent::__construct($requestParamsResolver, $helpers);
    }


    /**
     * @inheritDoc
     *
     * @throws \Throwable
     *
     * @param \SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface $responseMode
     * @param \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum[] $allowedServerRequestMethods
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        ResponseModeInterface $responseMode = new QueryResponseMode(),
        array $allowedServerRequestMethods = [HttpMethodsEnum::GET],
    ): ?Result {
        $loggerService->debug('RedirectUriRule::checkRule');
        $client = $currentResultBag->getOrFail(ClientRule::class)->getValue();
        if (! $client instanceof ClientEntityInterface) {
            throw new LogicException('Can not check redirect_uri, client is not ClientEntityInterface.');
        }

        $redirectUri = $this->requestParamsResolver->getAsStringBasedOnAllowedMethods(
            ParamsEnum::RedirectUri->value,
            $request,
            $allowedServerRequestMethods,
        );

        // On OAuth2 redirect_uri is optional if there is only one registered, however we will always require it
        // since this is OIDC oriented package and in OIDC this parameter is required.
        if ($redirectUri === null) {
            $loggerService->notice(
                'Request rejected: `redirect_uri` parameter is required but was not provided.',
                ['client_id' => $client->getIdentifier()],
            );
            throw OidcServerException::invalidRequest(ParamsEnum::RedirectUri->value);
        }

        $clientRedirectUri = $client->getRedirectUri();

        try {
            if (is_string($clientRedirectUri) && (strcmp($clientRedirectUri, $redirectUri) !== 0)) {
                throw OidcServerException::invalidClient($request);
            } elseif (
                is_array($clientRedirectUri) &&
                in_array($redirectUri, $clientRedirectUri, true) === false
            ) {
                throw OidcServerException::invalidRequest(ParamsEnum::RedirectUri->value);
            }
        } catch (Throwable $exception) {
            // The prefixes stand in for the registration a non-registered wallet does not have, so they are
            // offered to the generic client ClientRule hands such a wallet, and to nothing else: a registered
            // client is held to the redirect URIs it registered, in a credential request too.
            if (
                $client->isGeneric() &&
                $this->requestParamsResolver->isVciAuthorizationCodeRequestWithIssuerState(
                    $request,
                    $allowedServerRequestMethods,
                ) &&
                $this->moduleConfig->getVciEnabled() &&
                $this->moduleConfig->getVciAllowNonRegisteredClients()
            ) {
                $loggerService->debug(
                    'RedirectUriRule: Verifiable Credential capabilities with non-registered clients are enabled. ' .
                    'Checking for allowed redirect URI prefixes.',
                );

                /** @psalm-suppress MixedAssignment */
                foreach (
                    $this->moduleConfig->getVciAllowedRedirectUriPrefixesForNonRegisteredClients(
                    ) as $clientRedirectUriPrefix
                ) {
                    if (str_starts_with($redirectUri, (string)$clientRedirectUriPrefix)) {
                        $loggerService->debug(
                            'RedirectUriRule: Redirect URI param starts with allowed redirect URI prefix, continuing.',
                            ['redirect_uri' => $redirectUri, 'redirect_uri_prefix' => $clientRedirectUriPrefix],
                        );

                        $this->refuseAnHttpRedirectUriOtherThanANativeLoopbackOne(
                            $request,
                            $allowedServerRequestMethods,
                            $client,
                            $redirectUri,
                            $loggerService,
                        );

                        return new Result($this->getKey(), $redirectUri);
                    }
                }

                $loggerService->error(
                    'RedirectUriRule: Redirect URI param does not start with allowed redirect URI prefix, stopping.',
                    ['redirect_uri' => $redirectUri],
                );

                throw $exception;
            } else {
                $loggerService->debug(
                    'RedirectUriRule: Not a non-registered wallet in a credential request, or such wallets are ' .
                    'not allowed.',
                );
                $loggerService->error(
                    'RedirectUriRule: Redirect URI param does not correspond to the client redirect URI.',
                    ['redirect_uri' => $redirectUri, 'client_redirect_uri' => $clientRedirectUri],
                );
                throw $exception;
            }
        }

        $loggerService->debug(
            'RedirectUriRule: Redirect URI param corresponds to the client redirect URI.',
            ['redirect_uri' => $redirectUri, 'client_redirect_uri' => $clientRedirectUri],
        );

        $this->refuseAnHttpRedirectUriOtherThanANativeLoopbackOne(
            $request,
            $allowedServerRequestMethods,
            $client,
            $redirectUri,
            $loggerService,
        );

        return new Result($this->getKey(), $redirectUri);
    }


    /**
     * While issuance follows HAIP, an issuance request is answered at no `http` redirect URI but the loopback one of
     * a native client (FAPI 2.0 section 5.3.2.2, RFC 8252 section 7.3): a URI LOOPBACK_REDIRECT_URI_PATTERN matches,
     * whatever its port and path, of a client registered with `application_type` `native`. Judged at request time, so
     * a client registered by hand is held to it too; `https` and custom schemes are not affected, and the request is
     * not asked about for them. Refused without a redirect, since the redirect URI is what is refused.
     *
     * @param \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum[] $allowedServerRequestMethods
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    protected function refuseAnHttpRedirectUriOtherThanANativeLoopbackOne(
        ServerRequestInterface $request,
        array $allowedServerRequestMethods,
        ClientEntityInterface $client,
        string $redirectUri,
        LoggerService $loggerService,
    ): void {
        if (
            !$this->isHttpRedirectUri($redirectUri) ||
            !$this->requestParamsResolver->isVciHaipIssuanceRequest($request, $allowedServerRequestMethods)
        ) {
            return;
        }

        if (
            $client->getApplicationType() === ApplicationTypesEnum::Native->value &&
            preg_match(self::LOOPBACK_REDIRECT_URI_PATTERN, $redirectUri) === 1
        ) {
            return;
        }

        $loggerService->warning(
            'Request rejected: credential issuance following HAIP takes no http redirect URI but the loopback one ' .
            'of a native client.',
            ['client_id' => $client->getIdentifier(), 'redirect_uri' => $redirectUri],
        );

        throw OidcServerException::invalidRequest(
            ParamsEnum::RedirectUri->value,
            'Credential issuance following HAIP takes no http redirect URI but the loopback one (127.0.0.1 or ' .
            '[::1]) of a client registered with the native application type.',
        );
    }


    /**
     * Whether a browser takes the redirect URI for an `http` one: its scheme as the WHATWG URL Standard reads it,
     * after the leading and trailing spaces and control characters it strips and the tabs and newlines it removes,
     * so that none of them hides an `http` URI from refuseAnHttpRedirectUriOtherThanANativeLoopbackOne().
     */
    protected function isHttpRedirectUri(string $redirectUri): bool
    {
        $asABrowserReadsIt = (string)preg_replace('/[\t\n\r]/', '', trim($redirectUri, "\x00..\x20"));

        return preg_match('/^http:/i', $asABrowserReadsIt) === 1;
    }
}
