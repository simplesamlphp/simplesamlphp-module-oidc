<?php

declare(strict_types=1);

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * Copyright (C) 2018 by the Spanish Research and Academic Network.
 *
 * This code was developed by Universidad de Córdoba (UCO https://www.uco.es)
 * for the RedIRIS SIR service (SIR: http://www.rediris.es/sir)
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Module\oidc\Controllers;

use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface as OAuth2AuthorizationRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Auth\ProcessingChain;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\AuthorizationServer;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest;
use SimpleSAML\Module\oidc\Services\AuthenticationService;
use SimpleSAML\Module\oidc\Services\ErrorResponder;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\UiLocalesResolver;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class AuthorizationController
{
    public function __construct(
        private readonly AuthenticationService $authenticationService,
        private readonly AuthorizationServer $authorizationServer,
        private readonly ModuleConfig $moduleConfig,
        private readonly LoggerService $loggerService,
        private readonly PsrHttpBridge $psrHttpBridge,
        private readonly ErrorResponder $errorResponder,
        private readonly UiLocalesResolver $uiLocalesResolver,
        private readonly SspBridge $sspBridge,
    ) {
    }

    /**
     * @throws \Exception
     * @throws \SimpleSAML\Error\AuthSource
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Error\NotFound
     * @throws \SimpleSAML\Error\Exception
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \Throwable
     *
     * @deprecated 7.0.0 Will be moved to Symfony controller method
     * @see self::authorization()
     */
    public function __invoke(ServerRequestInterface $request): ResponseInterface
    {
        $queryParameters = $request->getQueryParams();
        $state = null;
        $this->loggerService->debug('AuthorizationController::invoke: Request parameters: ', $queryParameters);

        if (!isset($queryParameters[ProcessingChain::AUTHPARAM])) {
            $this->loggerService->debug('AuthorizationController::invoke: No AuthProcId query param.');
            $authorizationRequest = $this->authorizationServer->validateAuthorizationRequest($request);
            $this->setUiLanguage($authorizationRequest);
            $state = $this->authenticationService->processRequest($request, $authorizationRequest);
            // processState will trigger a redirect
        }

        $state ??= $this->authenticationService->manageState($queryParameters);
        $authorizationRequest = $this->authenticationService->getAuthorizationRequestFromState($state);

        // Validate any id_token_hint against the authenticated End-User before the user is resolved and (as a side
        // effect) associated with the client, so that a mismatched request leaves no relying party association
        // behind (which could otherwise later receive a back-channel logout for that End-User).
        if ($authorizationRequest instanceof AuthorizationRequest) {
            $this->validateIdTokenHint($authorizationRequest, $state);
        }

        $user = $this->authenticationService->getAuthenticateUser($state);

        $authorizationRequest->setUser($user);
        $authorizationRequest->setAuthorizationApproved(true);

        if ($authorizationRequest instanceof AuthorizationRequest) {
            $authorizationRequest->setIsCookieBasedAuthn($this->authenticationService->isCookieBasedAuthn());
            $authorizationRequest->setAuthSourceId($this->authenticationService->getAuthSourceId());
            $authorizationRequest->setSessionId($this->authenticationService->getSessionId());

            $this->validatePostAuthnAuthorizationRequest($authorizationRequest);
        }

        return $this->authorizationServer->completeAuthorizationRequest(
            $authorizationRequest,
            $this->psrHttpBridge->getResponseFactory()->createResponse(),
        );
    }

    /**
     * @param   Request  $request
     *
     * @return Response
     * @throws \SimpleSAML\Error\AuthSource
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Error\Error
     * @throws \SimpleSAML\Error\Exception
     * @throws \SimpleSAML\Error\NotFound
     * @throws \Throwable
     */
    public function authorization(Request $request): Response
    {
        try {
            /**
             * @psalm-suppress DeprecatedMethod Until we drop support for old public/*.php routes, we need to bridge
             * between PSR and Symfony HTTP messages.
             */
            $response = $this->psrHttpBridge->getHttpFoundationFactory()->createResponse(
                $this->__invoke($this->psrHttpBridge->getPsrHttpFactory()->createRequest($request)),
            );

            // If not already handled, allow CORS (for JS clients).
            if (!$response->headers->has('Access-Control-Allow-Origin')) {
                $response->headers->set('Access-Control-Allow-Origin', '*');
            }

            return $response;
        } catch (OAuthServerException $exception) {
            return $this->errorResponder->forException($exception);
        }
    }

    /**
     * Set the UI language for the current user agent based on the ui_locales authorization request parameter,
     * if any of the requested languages are available in SimpleSAMLphp. This is done using the standard
     * SimpleSAMLphp language cookie (same mechanism as when the user picks a language on any SimpleSAMLphp
     * page), so subsequent screens shown during the authentication flow (login page, consent...) are
     * rendered in the requested language. Per specification this is best-effort, so no error is raised
     * if none of the requested languages are available.
     *
     * The SimpleSAMLphp language cookie is a persistent, instance-wide preference, so an already present
     * cookie (an explicit language choice the user, or a previous interaction, has made) is not
     * overridden by the client-supplied ui_locales value.
     */
    protected function setUiLanguage(OAuth2AuthorizationRequestInterface $authorizationRequest): void
    {
        if (!$authorizationRequest instanceof AuthorizationRequest) {
            return;
        }

        $language = $this->uiLocalesResolver->resolve($authorizationRequest->getUiLocales());

        if ($language === null) {
            return;
        }

        if ($this->sspBridge->locale()->language()->getLanguageCookie() !== null) {
            $this->loggerService->debug(
                'AuthorizationController: not overriding existing language cookie with ui_locales parameter.',
                ['uiLocales' => $authorizationRequest->getUiLocales(), 'language' => $language],
            );
            return;
        }

        $this->loggerService->debug(
            'AuthorizationController: setting UI language based on ui_locales parameter.',
            ['uiLocales' => $authorizationRequest->getUiLocales(), 'language' => $language],
        );

        $this->sspBridge->locale()->language()->setLanguageCookie($language);
    }

    /**
     * Validate authorization request after the authn has been performed. For example, check if the
     * ACR claim has been requested and that authn performed satisfies it.
     *
     * @throws \Exception
     */
    protected function validatePostAuthnAuthorizationRequest(AuthorizationRequest $authorizationRequest): void
    {
        $this->validateAcr($authorizationRequest);
    }

    /**
     * Validate the `id_token_hint` authorization request parameter (if any) against the authenticated End-User.
     *
     * The hint is an ID Token previously issued by this OP; its issuer and signature were already validated early
     * (IdTokenHintRule) and its subject carried on the authorization request. Here, using the released post-authproc
     * attributes (the same ones from which the issued subject is derived), we verify that the authenticated End-User
     * matches the subject in the hint. Per OpenID Connect Core, the request must not be satisfied for a different
     * End-User than the one the hint identifies; if they differ we return `login_required` (the specification's
     * suggested error) rather than issuing a token/code for the wrong user. This applies to all prompt modes: with
     * `prompt=none` it prevents a silent response for a mismatched cookie session, and with interactive
     * authentication it rejects the request when a different End-User authenticated than the hint asked for (the
     * client can then retry, e.g. with `prompt=login`).
     *
     * This runs before the End-User is resolved and associated with the client, so a mismatch does not leave a
     * relying party association behind.
     *
     * @param array<array-key,mixed>|null $state
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    protected function validateIdTokenHint(AuthorizationRequest $authorizationRequest, ?array $state): void
    {
        $hintSubject = $authorizationRequest->getIdTokenHintSubject();
        if ($hintSubject === null) {
            return;
        }

        // No released attributes means no End-User to match the hint against, so the request can not be satisfied
        // for the End-User the hint identifies (subjectMatchesAttributes() returns false for an empty set).
        $attributes = (isset($state['Attributes']) && is_array($state['Attributes'])) ? $state['Attributes'] : [];

        if ($this->authenticationService->subjectMatchesAttributes($hintSubject, $attributes)) {
            return;
        }

        $this->loggerService->notice(
            'Authorization request rejected: the authenticated End-User does not match the `id_token_hint` subject.',
            ['client_id' => $authorizationRequest->getClient()->getIdentifier()],
        );

        throw OidcServerException::loginRequired(
            'Authenticated End-User does not match the id_token_hint subject.',
            $this->resolveRedirectUri($authorizationRequest),
            null,
            $authorizationRequest->getState(),
            $authorizationRequest->getResponseMode(),
        );
    }

    /**
     * Resolve the redirect URI to use for redirected error responses: the one validated for this request, or the
     * client's first registered redirect URI as a fallback.
     */
    protected function resolveRedirectUri(AuthorizationRequest $authorizationRequest): ?string
    {
        $redirectUri = $authorizationRequest->getRedirectUri();
        if ($redirectUri !== null) {
            return $redirectUri;
        }

        $clientRedirectUri = $authorizationRequest->getClient()->getRedirectUri();

        return is_array($clientRedirectUri) ? ($clientRedirectUri[0] ?? null) : $clientRedirectUri;
    }

    /**
     * @throws \Exception
     */
    protected function validateAcr(AuthorizationRequest $authorizationRequest): void
    {
        // If no ACRs requested, don't set ACR claim.
        if (($requestedAcrValues = $authorizationRequest->getRequestedAcrValues()) === null) {
            return;
        }

        // In order to check available ACRs, we have to know auth source and if authn was based on cookie.
        if (($authSourceId = $authorizationRequest->getAuthSourceId()) === null) {
            throw OidcServerException::serverError('authSourceId not set on authz request');
        }
        if (($isCookieBasedAuthn = $authorizationRequest->getIsCookieBasedAuthn()) === null) {
            throw OidcServerException::serverError('isCookieBasedAuthn not set on authz request');
        }

        $authSourceToAcrValuesMap = $this->moduleConfig->getAuthSourcesToAcrValuesMap();

        $availableAuthSourceAcrs = is_array($authSourceToAcrValuesMap[$authSourceId]) ?
        $authSourceToAcrValuesMap[$authSourceId] :
        [];
        $forcedAcrForCookieAuthentication = $this->moduleConfig->getForcedAcrValueForCookieAuthentication();

        if ($forcedAcrForCookieAuthentication !== null && $isCookieBasedAuthn) {
            $availableAuthSourceAcrs = [$forcedAcrForCookieAuthentication];
        }

        $isRequestedAcrEssential = empty($requestedAcrValues['essential']) ?
        false :
        boolval($requestedAcrValues['essential']);

        $acrs = !empty($requestedAcrValues['values']) && is_array($requestedAcrValues['values']) ?
        $requestedAcrValues['values'] :
        [];

        $matchedAcrs = array_intersect($availableAuthSourceAcrs, $acrs);

        // If we have matched ACRs, use the best (first) one (order is important).
        if (!empty($matchedAcrs)) {
            $authorizationRequest->setAcr((string)current($matchedAcrs));
            return;
        }

        // Since we don't have matched ACRs, and the client marked the requested claim as essential, error out.
        if ($isRequestedAcrEssential) {
            throw OidcServerException::accessDenied('could not satisfy requested ACR');
        }

        // If the ACR is not essential, we should return current session ACR (if we have one available)...
        if (! empty($availableAuthSourceAcrs)) {
            $authorizationRequest->setAcr((string)current($availableAuthSourceAcrs));
            return;
        }

        // ...according to spec we have to return acr claim, and we don't have one available (none configured)...
        $genericAcr = 'N/A';
        $message = sprintf(
            'No ACRs configured for current auth source, whilst specification mandates one. ' .
            'Falling back to generic ACR (%s).',
            $genericAcr,
        );
        $this->loggerService->warning($message);
        $authorizationRequest->setAcr($genericAcr);
    }
}
