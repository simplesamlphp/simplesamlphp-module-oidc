<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

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
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;

/**
 * @extends \SimpleSAML\Module\oidc\Server\RequestRules\Rules\AbstractRule<string>
 */
class ResponseTypeRule extends AbstractRule
{
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
     * @param \SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface $responseMode
     * @param \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum[] $allowedServerRequestMethods
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \SimpleSAML\Error\ConfigurationError When the enabled grant types can not be read.
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        ResponseModeInterface $responseMode = new QueryResponseMode(),
        array $allowedServerRequestMethods = [HttpMethodsEnum::GET],
    ): ?Result {
        $requestParams = $this->requestParamsResolver->getAllBasedOnAllowedMethods(
            $request,
            $allowedServerRequestMethods,
        );

        // A request without a response type is not judged here: no grant takes it, so the authorization endpoint
        // refuses it as it refuses any request no grant takes, and the pushed authorization request endpoint as one
        // missing a parameter. One which is not a string is not understood, and refused below as any other response
        // type which is not offered; a pushed request carrying one would otherwise be stored for a request_uri no
        // grant can redeem. The client is the one ClientRule resolved.
        /** @psalm-suppress MixedAssignment */
        $requestedResponseType = $requestParams[ParamsEnum::ResponseType->value] ?? null;

        if ($requestedResponseType === null) {
            return null;
        }

        // RFC 6749 section 3.1.1: a response type which is not understood is refused, and the order of the values
        // of a composite one does not matter. Grant selection does not settle the first: the implicit grant takes any
        // value with `id_token` and without `code` in it (`id_token example_extension`, say). So the requested value
        // is matched here against the response types this OP offers, those of its enabled grants
        // (ModuleConfig::getSupportedResponseTypes()), whoever the client is, and is answered in the form the OP
        // offers it: the rules after this one compare with that form. AuthorizationServer runs this rule before it
        // chooses a grant, and the pushed authorization request endpoint with its other rules, so that such a request
        // is refused before a grant's own policy or a login, and before a request_uri is issued for it.

        $responseType = is_string($requestedResponseType) ? $this->matchingResponseType(
            $requestedResponseType,
            $this->moduleConfig->getSupportedResponseTypes(),
        ) : null;

        if ($responseType === null) {
            $loggerService->notice(
                'ResponseTypeRule: response_type not supported.',
                ['response_type' => is_string($requestedResponseType) ? $requestedResponseType : 'not a string'],
            );
            throw OidcServerException::unsupportedResponseType(
                $currentResultBag->getOrFail(ClientRedirectUriRule::class)->getValue(),
                $currentResultBag->getOrFail(StateRule::class)->getValue(),
                $responseMode,
            );
        }

        // Per-client enforcement: if the client has explicitly registered a non-empty response_types list, the
        // requested response_type must be one of them. We enforce only when the value was explicitly registered
        // (present and non-empty in the client's metadata); clients that do not have it configured - or have it as
        // an empty list - are not constrained, preserving behavior for manually-managed and pre-DCR clients.
        // Dynamically registered clients always have it (the OIDC DCR default is applied at registration).
        $client = $currentResultBag->getOrFail(ClientRule::class)->getValue();
        // getResponseTypes() returns the raw registered value (empty array when nothing is registered - it does not
        // synthesize the OIDC DCR spec default), so an empty list means "not configured" and is not enforced.
        $registeredResponseTypes = ($client instanceof ClientEntityInterface) ? $client->getResponseTypes() : [];

        // The OP offers the response type, and this client may not use it: RFC 6749 sections 4.1.2.1 and 4.2.2.1
        // call that `unauthorized_client`, and keep `unsupported_response_type` for one the authorization server
        // does not offer at all, above.
        if (
            $registeredResponseTypes !== [] &&
            $this->matchingResponseType($responseType, $registeredResponseTypes) === null
        ) {
            $loggerService->error(
                'ResponseTypeRule: response_type not registered for client.',
                ['response_type' => $responseType, 'registered' => $registeredResponseTypes],
            );
            $redirectUri = $currentResultBag->getOrFail(ClientRedirectUriRule::class)->getValue();
            $state = $currentResultBag->getOrFail(StateRule::class)->getValue();
            throw OidcServerException::unauthorizedClient(
                'The response type is not registered for the client.',
                $redirectUri,
                null,
                $state,
                $responseMode,
            );
        }

        return new Result($this->getKey(), $responseType);
    }


    /**
     * The one of the response types which has the requested one's values, in whatever order (RFC 6749 section
     * 3.1.1), or null when none has. Values are separated by single spaces, so a doubled space or a repeated value
     * matches nothing.
     *
     * Reordering the values does not change the length, so only a response type as long as the requested one is
     * compared, and the requested one is split only then: a value of any length, which a request can carry, is never
     * split into an array as long as itself.
     *
     * @param string[] $responseTypes
     */
    protected function matchingResponseType(string $requested, array $responseTypes): ?string
    {
        foreach ($responseTypes as $responseType) {
            if (
                strlen($responseType) === strlen($requested) &&
                $this->valuesOf($responseType) === $this->valuesOf($requested)
            ) {
                return $responseType;
            }
        }

        return null;
    }


    /**
     * @return string[]
     */
    protected function valuesOf(string $responseType): array
    {
        $values = explode(' ', $responseType);
        sort($values);

        return $values;
    }
}
