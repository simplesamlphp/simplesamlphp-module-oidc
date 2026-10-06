<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\Grants;

use DateInterval;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface as OAuth2AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface as OAuth2ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface as OAuth2AuthCodeRepositoryInterface;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest as OAuth2AuthorizationRequest;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface as OAuth2AuthorizationRequestInterface;
use League\OAuth2\Server\ResponseTypes\RedirectResponse;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum;
use SimpleSAML\Module\oidc\Entities\AuthCodeEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\AccessTokenEntityInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\AuthCodeEntityInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\RefreshTokenEntityInterface;
use SimpleSAML\Module\oidc\Factories\Entities\AccessTokenEntityFactory;
use SimpleSAML\Module\oidc\Factories\Entities\AuthCodeEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AuthCodeRepository;
use SimpleSAML\Module\oidc\Repositories\Interfaces\AccessTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Repositories\Interfaces\RefreshTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Repositories\IssuerStateRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\AuthorizationDetailsRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\PreAuthorizedCodeClientRule;
use SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Server\TokenIssuers\RefreshTokenIssuer;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\AccessTokenClaimsResolver;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Module\oidc\Utils\SubjectResolver;
use SimpleSAML\Module\oidc\VerifiableCredentials\TxCodeAttemptLimiter;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\GrantTypesEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;

use function hash_equals;

/**
 * @psalm-suppress PropertyNotSetInConstructor
 */
class PreAuthCodeGrant extends AuthCodeGrant
{
    /**
     * The parent's collaborators, and the limit on attempts at a code's Transaction Code.
     *
     * @throws \Exception
     */
    public function __construct(
        OAuth2AuthCodeRepositoryInterface $authCodeRepository,
        AccessTokenRepositoryInterface $accessTokenRepository,
        RefreshTokenRepositoryInterface $refreshTokenRepository,
        DateInterval $authCodeTTL,
        RequestRulesManager $requestRulesManager,
        RequestParamsResolver $requestParamsResolver,
        AccessTokenEntityFactory $accessTokenEntityFactory,
        AuthCodeEntityFactory $authCodeEntityFactory,
        RefreshTokenIssuer $refreshTokenIssuer,
        Helpers $helpers,
        LoggerService $loggerService,
        UserRepository $userRepository,
        SubjectResolver $subjectResolver,
        AccessTokenClaimsResolver $accessTokenClaimsResolver,
        ModuleConfig $moduleConfig,
        IssuerStateRepository $issuerStateRepository,
        protected readonly TxCodeAttemptLimiter $txCodeAttemptLimiter,
    ) {
        parent::__construct(
            $authCodeRepository,
            $accessTokenRepository,
            $refreshTokenRepository,
            $authCodeTTL,
            $requestRulesManager,
            $requestParamsResolver,
            $accessTokenEntityFactory,
            $authCodeEntityFactory,
            $refreshTokenIssuer,
            $helpers,
            $loggerService,
            $userRepository,
            $subjectResolver,
            $accessTokenClaimsResolver,
            $moduleConfig,
            $issuerStateRepository,
        );
    }


    public function getIdentifier(): string
    {
        return GrantTypesEnum::PreAuthorizedCode->value;
    }


    /**
     * Reimplemented to disable authz requests (code is pre-authorized).
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @return bool
     */
    public function canRespondToAuthorizationRequest(ServerRequestInterface $request): bool
    {
        return false;
    }


    /**
     * Check if the authorization request is OIDC candidate (can respond with ID token).
     */
    public function isOidcCandidate(
        OAuth2AuthorizationRequest $authorizationRequest,
    ): bool {
        return false;
    }


    /**
     * @inheritDoc
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \JsonException
     */
    public function completeAuthorizationRequest(
        OAuth2AuthorizationRequestInterface $authorizationRequest,
    ): ResponseTypeInterface {
        throw OidcServerException::serverError('Not implemented');
    }


    /**
     * This is reimplementation of OAuth2 completeAuthorizationRequest method with addition of nonce handling.
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException
     * @throws \JsonException
     */
    public function completeOidcAuthorizationRequest(
        AuthorizationRequest $authorizationRequest,
    ): RedirectResponse {
        throw OidcServerException::serverError('Not implemented');
    }


    /**
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException
     */
    protected function issueOidcAuthCode(
        DateInterval $authCodeTTL,
        OAuth2ClientEntityInterface $client,
        string $userIdentifier,
        string $redirectUri,
        AuthorizationRequest $authorizationRequest,
    ): AuthCodeEntityInterface {
        throw OidcServerException::serverError('Not implemented');
    }


    /**
     * Reimplementation for Pre-authorized Code.
     *
     * Client authentication is optional for this grant (OpenID4VCI 1.0, section 6.1), so the wallet is not put
     * through ClientAuthenticationRule, which refuses a request presenting no method. PreAuthorizedCodeClientRule
     * authenticates the wallet when it presents credentials, takes a bare `client_id` as the self-declared
     * identifier of a non-registered wallet, and identifies nobody for an anonymous request. A registered
     * wallet gets the access token issued to itself. The code is created for the generic VCI client, since no
     * wallet is known when the offer is made, and that is the client a non-registered wallet's token is issued
     * to, with the identifier the wallet declared bound to the token in the way the authorization code flow
     * binds one; an anonymous request gets the same token with nothing bound.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param \League\OAuth2\Server\ResponseTypes\ResponseTypeInterface $responseType
     * @param \DateInterval $accessTokenTTL
     *
     * @return \League\OAuth2\Server\ResponseTypes\ResponseTypeInterface
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \JsonException
     * @throws \Throwable
     *
     */
    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        DateInterval $accessTokenTTL,
    ): ResponseTypeInterface {
        $this->loggerService->debug('PreAuthCodeGrant::respondToAccessTokenRequest');

        // With vci_require_dpop, no pre-authorized code is redeemed without a DPoP proof. Settled first, before the
        // code is looked up, so that a request which fails it spends no Transaction Code attempt.
        $verifiedDpopProof = $this->getVerifiedDpopProof($request);

        if ($verifiedDpopProof === null && $this->moduleConfig->getVciRequireDpop()) {
            $this->loggerService->notice(
                'Token request rejected: DPoP is required for credential issuance (vci_require_dpop), and the ' .
                'pre-authorized code request carries no DPoP proof.',
            );
            throw OidcServerException::invalidDpopProof('A DPoP proof is required for credential issuance.');
        }

        $preAuthorizedCodeId = $this->requestParamsResolver->getAsStringBasedOnAllowedMethods(
            ParamsEnum::PreAuthorizedCode->value,
            $request,
            $this->allowedTokenHttpMethods,
        );

        if (empty($preAuthorizedCodeId)) {
            $this->loggerService->error('Empty pre-authorized code ID.');
            throw OidcServerException::invalidRequest(ParamsEnum::PreAuthorizedCode->value);
        }

        if (!is_a($this->authCodeRepository, AuthCodeRepository::class)) {
            throw OidcServerException::serverError('Unexpected auth code repository entity type.');
        }

        $preAuthorizedCode = $this->authCodeRepository->findById($preAuthorizedCodeId);

        if (
            is_null($preAuthorizedCode)  ||
            !is_a($preAuthorizedCode, AuthCodeEntity::class)
        ) {
            $this->loggerService->notice('Token request rejected: pre-authorized code was not found.');
            throw OidcServerException::invalidGrant('Invalid pre-authorized code.');
        }

        // From here on, the code as stored rather than as sent: a database whose collation ignores case (MySQL's
        // defaults do, and the older ones trailing spaces as well) finds the code under other spellings too, and
        // each spelling would otherwise get a count of Transaction Code attempts of its own.
        $preAuthorizedCodeId = $preAuthorizedCode->getIdentifier();

        $client = $preAuthorizedCode->getClient();

        $this->validateAuthorizationCode($preAuthorizedCode, $client, $request, $preAuthorizedCode);

        // Validate Transaction Code. Not sent means null or an empty string; anything else, "0" included, is
        // a Transaction Code. OpenID4VCI 1.0 section 6.3 has a missing one and an unexpected one answered with
        // invalid_request, and a wrong one with invalid_grant. A code which carries one carries a non-empty
        // value other than "0": the generator draws four digits, and AuthCodeEntityFactory::fromState() reads
        // a stored "" or "0" as none.
        $txCodeParam = $this->requestParamsResolver->getAsStringBasedOnAllowedMethods(
            ParamsEnum::TxCode->value,
            $request,
            $this->allowedTokenHttpMethods,
        );
        $txCodeSent = $txCodeParam !== null && $txCodeParam !== '';

        if (($preAuthorizedCodeTxCode = $preAuthorizedCode->getTxCode()) !== null) {
            $this->loggerService->debug('Validating transaction code.');

            if (!$txCodeSent) {
                $this->loggerService->warning('Empty transaction code parameter.');
                throw OidcServerException::invalidRequest(ParamsEnum::TxCode->value, 'Transaction Code is missing.');
            }

            // The attempt is taken before the Transaction Code is looked at, so that a right one spends an
            // attempt as a wrong one does, and is not given back if a rule refuses the request later. Refused
            // with the hint an unknown code and a consumed one share.
            if (
                !$this->txCodeAttemptLimiter->admitAttempt(
                    $preAuthorizedCodeId,
                    $preAuthorizedCode->getExpiryDateTime(),
                )
            ) {
                $this->loggerService->warning(
                    'Token request rejected: no attempts are left at the transaction code of the pre-authorized ' .
                    'code.',
                );
                throw OidcServerException::invalidGrant('Invalid pre-authorized code.');
            }

            if (!hash_equals($preAuthorizedCodeTxCode, $txCodeParam)) {
                $this->loggerService->warning(
                    'Transaction code parameter value does not match pre-authorized code transaction code.',
                );
                throw OidcServerException::invalidGrant('Transaction Code is invalid.');
            }
        } elseif ($txCodeSent) {
            $this->loggerService->warning(
                'Token request rejected: a transaction code was sent for a pre-authorized code which has none.',
            );
            throw OidcServerException::invalidRequest(ParamsEnum::TxCode->value, 'Transaction Code is not expected.');
        }

        $resultBag = $this->requestRulesManager->check(
            $request,
            [PreAuthorizedCodeClientRule::class, AuthorizationDetailsRule::class],
            // Response mode is not relevant for token request, as there is
            // no redirection, but we need to provide something to execute rules.
            new QueryResponseMode(),
            $this->allowedTokenHttpMethods,
        );

        // Null for an anonymous request.
        $walletClient = $resultBag->get(PreAuthorizedCodeClientRule::class)?->getValue();
        $registeredClient = $walletClient?->getRegisteredClient();

        // The token goes to the registered wallet when there is one, and to the code's client, the generic
        // VCI stand-in, otherwise, bound to the identifier a non-registered wallet declared - nothing, for an
        // anonymous request. The binding stands in for a registration, so a registered wallet gets none.
        $tokenClient = $registeredClient ?? $client;
        $boundClientId = $registeredClient === null ? $walletClient?->getIdentifier() : null;

        if (!$tokenClient instanceof ClientEntityInterface) {
            throw OidcServerException::serverError('Unexpected Client Entity instance.');
        }

        // A wallet registered with dpop_bound_access_tokens (RFC 9449 section 5.2) gets no token without a DPoP
        // proof. Its registration is known only here, after a Transaction Code attempt was counted and before the
        // code is consumed: only a wallet which omits the proof it registered to send loses an attempt.
        if ($verifiedDpopProof === null && $tokenClient->getDpopBoundAccessTokens()) {
            $this->loggerService->notice(
                'Token request rejected: the client is registered to use DPoP for every token request ' .
                '(dpop_bound_access_tokens), and the pre-authorized code request carries no DPoP proof.',
                ['client_id' => $tokenClient->getIdentifier()],
            );
            throw OidcServerException::invalidDpopProof(
                'A DPoP proof is required: the client is registered with dpop_bound_access_tokens.',
            );
        }

        $userIdentifier = $preAuthorizedCode->getUserIdentifier() ?
        (string) $preAuthorizedCode->getUserIdentifier() :
        null;

        $scopes = $this->offeredScopes($preAuthorizedCode, $tokenClient, $userIdentifier);

        $authorizationDetails = $resultBag->get(AuthorizationDetailsRule::class)?->getValue();
        $scopes = $this->scopesRequestedByAuthorizationDetails($authorizationDetails, $scopes);

        // The token is bound to the key of the request's DPoP proof, if any, and lives as long as a token for
        // credential issuance does; settled before the code is consumed, so that a failure here spends nothing.
        $dpopJkt = $verifiedDpopProof?->getJwkThumbprint();
        $accessTokenTTL = $this->accessTokenTtlFor($accessTokenTTL, FlowTypeEnum::VciPreAuthorizedCode, $dpopJkt);

        // Consume immediately before token issuance. The conditional database update is the
        // authoritative replay guard, so only one concurrent request can proceed. If token
        // persistence subsequently fails, the code remains consumed (fail closed).
        if (!$this->authCodeRepository->consumePreAuthorizedCode($preAuthorizedCodeId)) {
            $this->loggerService->notice(
                'Token request rejected: pre-authorized code was already consumed or is no longer valid.',
            );
            throw OidcServerException::invalidGrant('Invalid pre-authorized code.');
        }

        // Issue and persist new access token
        $accessToken = $this->issueAccessToken(
            $accessTokenTTL,
            $tokenClient,
            $userIdentifier,
            $scopes,
            $preAuthorizedCodeId,
            flowTypeEnum: FlowTypeEnum::VciPreAuthorizedCode,
            authorizationDetails: $authorizationDetails,
            boundClientId: $boundClientId,
            dpopJkt: $dpopJkt,
        );

        $this->getEmitter()->emit(new RequestEvent(RequestEvent::ACCESS_TOKEN_ISSUED, $request));
        $responseType->setAccessToken($accessToken);

        $this->loggerService->notice(
            'Pre-authorized code redeemed; access token issued.',
            ['client_id' => $tokenClient->getIdentifier(), 'bound_client_id' => $boundClientId],
        );

        return $responseType;
    }


    /**
     * The scopes of the access token: the credential configurations the Credential Offer offered, which the code
     * holds as its scopes (CredentialOfferUriFactory), so that the token is valid only for those (OpenID4VCI 1.0
     * section 6.1 recommends it), and of those only the ones the client the token is issued to may have, as in
     * the authorization code grant -- all of them for the generic VCI client, the registered ones for a
     * registered wallet. A configuration no longer supported is left out, and so is `openid`, which the code
     * also holds: the token is for the credential endpoint, and a pre-authorized one never carried it.
     *
     * @return \League\OAuth2\Server\Entities\ScopeEntityInterface[]
     */
    protected function offeredScopes(
        AuthCodeEntity $preAuthorizedCode,
        OAuth2ClientEntityInterface $tokenClient,
        ?string $userIdentifier,
    ): array {
        $configurationIds = $this->moduleConfig->getVciCredentialConfigurationIdsSupported();

        $offeredScopes = array_values(array_filter(
            $preAuthorizedCode->getScopes(),
            fn(ScopeEntityInterface $scope): bool => in_array($scope->getIdentifier(), $configurationIds, true),
        ));

        return array_values($this->scopeRepository->finalizeScopes(
            $offeredScopes,
            $this->getIdentifier(),
            $tokenClient,
            $userIdentifier,
        ));
    }


    /**
     * authorization_details in the token request name the configurations the wallet wants the token for
     * (OpenID4VCI 1.0 section 6.1.1), and each has to be one the token is granted, or the request is refused
     * (RFC 9396 section 6). Checked before the code is consumed, so a wallet which asked for too much can ask
     * again. The token is then for those only: the credential endpoint lets a token which carries
     * authorization_details name nothing else (by credential_identifier), and its scopes, and the claims they
     * release, say no more than that. Without authorization_details the scopes stay as granted.
     *
     * @param mixed[]|null $authorizationDetails As AuthorizationDetailsRule validated them.
     * @param \League\OAuth2\Server\Entities\ScopeEntityInterface[] $scopes
     * @return \League\OAuth2\Server\Entities\ScopeEntityInterface[]
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    protected function scopesRequestedByAuthorizationDetails(?array $authorizationDetails, array $scopes): array
    {
        if ($authorizationDetails === null) {
            return $scopes;
        }

        $granted = array_map(fn(ScopeEntityInterface $scope): string => $scope->getIdentifier(), $scopes);
        $requested = [];

        /** @psalm-suppress MixedAssignment */
        foreach ($authorizationDetails as $authorizationDetail) {
            /** @psalm-suppress MixedAssignment */
            $credentialConfigurationId = is_array($authorizationDetail) ?
            ($authorizationDetail[ClaimsEnum::CredentialConfigurationId->value] ?? null) :
            null;

            if (is_string($credentialConfigurationId) && in_array($credentialConfigurationId, $granted, true)) {
                $requested[] = $credentialConfigurationId;
                continue;
            }

            $this->loggerService->notice(
                'Token request rejected: `authorization_details` name a credential configuration the ' .
                'pre-authorized code does not grant.',
            );
            throw OidcServerException::invalidAuthorizationDetails(
                'The pre-authorized code does not grant the credential configuration requested.',
            );
        }

        return array_values(array_filter(
            $scopes,
            fn(ScopeEntityInterface $scope): bool => in_array($scope->getIdentifier(), $requested, true),
        ));
    }


    /**
     * Reimplementation because of private parent access
     *
     * @param object $authCodePayload
     * @param \League\OAuth2\Server\Entities\ClientEntityInterface $client
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    protected function validateAuthorizationCode(
        object $authCodePayload,
        OAuth2ClientEntityInterface $client,
        ServerRequestInterface $request,
        AuthCodeEntity $storedAuthCodeEntity,
    ): void {
        $this->loggerService->debug('PreAuthCodeGrant::validateAuthorizationCode');

        if (!$storedAuthCodeEntity->isVciPreAuthorized()) {
            $this->loggerService->error('Pre-authorized code is not pre-authorized.');
            throw OidcServerException::invalidGrant('Pre-authorized code is not pre-authorized.');
        }

        if ($storedAuthCodeEntity->getExpiryDateTime()->getTimestamp() < time()) {
            $this->loggerService->error('Pre-authorized code is expired.');

            throw OidcServerException::invalidGrant('Pre-authorized code is expired.');
        }

        if ($storedAuthCodeEntity->isRevoked()) {
            $this->loggerService->error('Pre-authorized code is revoked.');
            throw OidcServerException::invalidGrant('Pre-authorized code is revoked.');
        }

        $this->loggerService->debug('PreAuthCodeGrant::validateAuthorizationCode passed.');
    }


    /**
     * @inheritDoc
     * @throws \Throwable
     */
    public function validateAuthorizationRequestWithRequestRules(
        ServerRequestInterface $request,
        ResultBagInterface $resultBag,
    ): OAuth2AuthorizationRequestInterface {
        throw OidcServerException::serverError('Not implemented');
    }


    /**
     * @param \League\OAuth2\Server\Entities\AccessTokenEntityInterface $accessToken
     * @param string|null $authCodeId
     * @return \SimpleSAML\Module\oidc\Entities\Interfaces\RefreshTokenEntityInterface|null
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException
     */
    protected function issueRefreshToken(
        OAuth2AccessTokenEntityInterface $accessToken,
        ?string $authCodeId = null,
    ): ?RefreshTokenEntityInterface {
        if (! is_a($accessToken, AccessTokenEntityInterface::class)) {
            throw OidcServerException::serverError('Unexpected access token entity type.');
        }

        return $this->refreshTokenIssuer->issue(
            $accessToken,
            $this->refreshTokenTTL,
            $authCodeId,
            self::MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS,
        );
    }
}
