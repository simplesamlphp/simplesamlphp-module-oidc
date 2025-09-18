<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\Grants;

use DateInterval;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface as OAuth2AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface as OAuth2ClientEntityInterface;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest as OAuth2AuthorizationRequest;
use League\OAuth2\Server\ResponseTypes\RedirectResponse;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum;
use SimpleSAML\Module\oidc\Entities\AuthCodeEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\AccessTokenEntityInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\AuthCodeEntityInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\RefreshTokenEntityInterface;
use SimpleSAML\Module\oidc\Repositories\AuthCodeRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\AuthorizationDetailsRule;
use SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest;
use SimpleSAML\OpenID\Codebooks\GrantTypesEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;

class PreAuthCodeGrant extends AuthCodeGrant
{
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
        OAuth2AuthorizationRequest $authorizationRequest,
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

        // TODO mivanci client authentication?

        $this->loggerService->debug(
            'PreAuthCodeGrant::respondToAccessTokenRequest: Request parameters: ',
            $this->requestParamsResolver->getAllFromRequest($request),
        );

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
            $this->loggerService->error('Invalid pre-authorized code ID. Value was: ' . $preAuthorizedCodeId);
            throw OidcServerException::invalidGrant('Invalid pre-authorized code.');
        }

        $client = $preAuthorizedCode->getClient();

        $this->validateAuthorizationCode($preAuthorizedCode, $client, $request, $preAuthorizedCode);

        // Validate Transaction Code.
        if (($preAuthorizedCodeTxCode = $preAuthorizedCode->getTxCode()) !== null) {
            $this->loggerService->debug('Validating transaction code ' . $preAuthorizedCodeTxCode);
            $txCodeParam = $this->requestParamsResolver->getAsStringBasedOnAllowedMethods(
                ParamsEnum::TxCode->value,
                $request,
                $this->allowedTokenHttpMethods,
            );

            if (empty($txCodeParam)) {
                $this->loggerService->warning('Empty transaction code parameter.');
                throw OidcServerException::invalidRequest(ParamsEnum::TxCode->value, 'Transaction Code is missing.');
            }

            $this->loggerService->debug('Transaction code parameter value: ' . $txCodeParam);

            if ($preAuthorizedCodeTxCode !== $txCodeParam) {
                $this->loggerService->warning(
                    'Transaction code parameter value does not match pre-authorized code transaction code.',
                    ['txCodeParam' => $txCodeParam, 'preAuthorizedCodeTxCode' => $preAuthorizedCodeTxCode,],
                );
                throw OidcServerException::invalidRequest(ParamsEnum::TxCode->value, 'Transaction Code is invalid.');
            }
        }

        $resultBag = $this->requestRulesManager->check(
            $request,
            [AuthorizationDetailsRule::class],
            false,
            $this->allowedTokenHttpMethods,
        );

        $clientId = $this->requestParamsResolver->getAsStringBasedOnAllowedMethods(
            ParamsEnum::ClientId->value,
            $request,
            $this->allowedTokenHttpMethods,
        );

        /** @var ?array $authorizationDetails */
        $authorizationDetails = $resultBag->get(AuthorizationDetailsRule::class)?->getValue();

        // Issue and persist new access token
        $accessToken = $this->issueAccessToken(
            $accessTokenTTL,
            $client,
            $preAuthorizedCode->getUserIdentifier() ? (string) $preAuthorizedCode->getUserIdentifier() : null,
            [], // TODO mivanci handle scopes
            $preAuthorizedCodeId,
            flowTypeEnum: FlowTypeEnum::VciPreAuthorizedCode,
            authorizationDetails: $authorizationDetails,
            boundClientId: $clientId,
        );

        $this->getEmitter()->emit(new RequestEvent(RequestEvent::ACCESS_TOKEN_ISSUED, $request));
        $responseType->setAccessToken($accessToken);


        // TODO mivanci revoke pre-authorized code or let it expire only after access token is issued?
        // $this->authCodeRepository->revokeAuthCode($preAuthorizedCode);

        return $responseType;
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
            $this->loggerService->error(
                'Pre-authorized code is not pre-authorized. ID was: ',
                ['preAuthCodeId' => $storedAuthCodeEntity->getIdentifier()],
            );
            throw OidcServerException::invalidGrant('Pre-authorized code is not pre-authorized.');
        }

        if ($storedAuthCodeEntity->getExpiryDateTime()->getTimestamp() < time()) {
            $this->loggerService->error(
                'Pre-authorized code is expired. ID was: ',
                ['preAuthCodeId' => $storedAuthCodeEntity->getIdentifier()],
            );

            throw OidcServerException::invalidGrant('Pre-authorized code is expired.');
        }

        if ($storedAuthCodeEntity->isRevoked()) {
            $this->loggerService->error(
                'Pre-authorized code is revoked. ID was: ',
                ['preAuthCodeId' => $storedAuthCodeEntity->getIdentifier()],
            );
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
    ): OAuth2AuthorizationRequest {
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
