<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\ResponseTypes;

use League\OAuth2\Server\CryptKeyInterface;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Repositories\Interfaces\IdentityProviderInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\ResponseTypes\Interfaces\AcrResponseTypeInterface;
use SimpleSAML\Module\oidc\Server\ResponseTypes\Interfaces\AuthTimeResponseTypeInterface;
use SimpleSAML\Module\oidc\Server\ResponseTypes\Interfaces\NonceResponseTypeInterface;
use SimpleSAML\Module\oidc\Server\ResponseTypes\Interfaces\SessionIdResponseTypeInterface;
use SimpleSAML\Module\oidc\Services\IdTokenBuilder;
use SimpleSAML\Module\oidc\Services\LoggerService;

use function array_merge;
use function json_encode;
use function time;

/**
 * Class IdTokenResponse.
 *
 * @author Steve Rhoades <sedonami@gmail.com>
 * @license http://opensource.org/licenses/MIT MIT
 *
 * @see https://github.com/steverhoades/oauth2-openid-connect-server/blob/master/src/IdTokenResponse.php
 *
 * @psalm-suppress PropertyNotSetInConstructor
 */
class TokenResponse extends BearerTokenResponse implements
    // phpcs:ignore
    NonceResponseTypeInterface,
    // phpcs:ignore
    AuthTimeResponseTypeInterface,
    // phpcs:ignore
    AcrResponseTypeInterface,
    // phpcs:ignore
    SessionIdResponseTypeInterface
{
    protected ?string $nonce = null;

    protected ?int $authTime = null;

    protected ?string $acr = null;

    protected ?string $sessionId = null;


    public function __construct(
        private readonly IdentityProviderInterface $identityProvider,
        protected IdTokenBuilder $idTokenBuilder,
        CryptKeyInterface $privateKey,
        protected LoggerService $loggerService,
    ) {
        $this->privateKey = $privateKey;
    }


    /**
     * League's own body (BearerTokenResponse, which builds the refresh token payload inline and offers no hook
     * for it) with one addition: the payload also carries the access token's subject as 'sub', next to the
     * internal 'user_id'. RefreshTokenGrant reads it back so the refreshed tokens name the End-User as the
     * original ID token did (OpenID Connect Core 1.0 section 12.2), whatever the user's attributes say by
     * then, and the introspection endpoint reports it for the refresh token.
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \Exception
     */
    public function generateHttpResponse(ResponseInterface $response): ResponseInterface
    {
        $accessToken = $this->accessToken;
        if ($accessToken instanceof AccessTokenEntity === false) {
            throw new RuntimeException('AccessToken must be ' . AccessTokenEntity::class);
        }

        $expireDateTime = $accessToken->getExpiryDateTime()->getTimestamp();

        $responseParams = [
            'token_type'   => 'Bearer',
            'expires_in'   => $expireDateTime - time(),
            'access_token' => $accessToken->toString(),
        ];

        // League leaves the property unset until a grant sets it.
        /** @psalm-suppress RedundantPropertyInitializationCheck */
        if (isset($this->refreshToken)) {
            $refreshTokenPayload = [
                'client_id'        => $accessToken->getClient()->getIdentifier(),
                'refresh_token_id' => $this->refreshToken->getIdentifier(),
                'access_token_id'  => $accessToken->getIdentifier(),
                'scopes'           => $accessToken->getScopes(),
                'user_id'          => $accessToken->getUserIdentifier(),
                'expire_time'      => $this->refreshToken->getExpiryDateTime()->getTimestamp(),
            ];

            // Every access token minted for a user carries one; an entity built without it (none is, on this
            // path) simply leaves the field out, which the grant reads as "resolve afresh".
            if (($subject = $accessToken->getSubject()) !== null) {
                $refreshTokenPayload['sub'] = $subject;
            }

            $refreshTokenPayload = json_encode($refreshTokenPayload);

            if ($refreshTokenPayload === false) {
                throw new LogicException('Error encountered JSON encoding the refresh token payload');
            }

            $responseParams['refresh_token'] = $this->encrypt($refreshTokenPayload);
        }

        $responseParams = json_encode(array_merge($this->getExtraParams($accessToken), $responseParams));

        if ($responseParams === false) {
            throw new LogicException('Error encountered JSON encoding response parameters');
        }

        $response = $response
            ->withStatus(200)
            ->withHeader('pragma', 'no-cache')
            ->withHeader('cache-control', 'no-store')
            ->withHeader('content-type', 'application/json; charset=UTF-8');

        $response->getBody()->write($responseParams);

        return $response;
    }


    /**
     * @param \League\OAuth2\Server\Entities\AccessTokenEntityInterface $accessToken
     * @return array
     * @throws \Exception
     */
    protected function getExtraParams(AccessTokenEntityInterface $accessToken): array
    {
        if ($accessToken instanceof AccessTokenEntity === false) {
            throw new RuntimeException('AccessToken must be ' . AccessTokenEntity::class);
        }

        $extraParams = [];

        if ($this->isOpenIDRequest($accessToken->getScopes())) {
            $extraParams = [
                ...$extraParams,
                ...$this->prepareIdTokenExtraParam($accessToken),
            ];
        }

        // For VCI, in token response for authorization code flow we need to return authorization details.
        if (
            ($flowType = $accessToken->getFlowTypeEnum()) !== null &&
            $flowType->isVciFlow() &&
            $accessToken->getAuthorizationDetails() !== null
        ) {
            $extraParams = [
                ...$extraParams,
                ...$this->prepareVciAuthorizationDetailsExtraParam($accessToken),
            ];
        }

        return array_filter($extraParams);
    }


    protected function prepareIdTokenExtraParam(AccessTokenEntity $accessToken): array
    {
        $userIdentifier = $accessToken->getUserIdentifier();

        if (empty($userIdentifier)) {
            throw OidcServerException::accessDenied('No user identifier present in AccessToken.');
        }

        $userEntity = $this->identityProvider->getUserEntityByIdentifier($userIdentifier);

        if (empty($userEntity)) {
            throw OidcServerException::accessDenied('No user available for provided user identifier.');
        }

        // Release the user's (scope-derived) claims in the ID Token when the client is configured to (the
        // administrator-only `add_claims_to_id_token` property). Otherwise such claims remain available only at
        // the UserInfo endpoint in the authorization code flow.
        $client = $accessToken->getClient();
        $addClaimsToIdToken = $client instanceof ClientEntity && $client->getAddClaimsToIdToken();

        //$token = $this->idTokenBuilder->build(
        $token = $this->idTokenBuilder->buildFor(
            $userEntity,
            $accessToken,
            $addClaimsToIdToken,
            true,
            $this->getNonce(),
            $this->getAuthTime(),
            $this->getAcr(),
            $this->getSessionId(),
        );

        return [
            'id_token' => $token->getToken(),
        ];
    }


    protected function prepareVciAuthorizationDetailsExtraParam(AccessTokenEntity $accessToken): array
    {
        $normalizedAuthorizationDetails = [];

        $this->loggerService->debug(
            'TokenResponse::prepareAuthorizationDetailsExtraParam',
            ['accessTokenAuthorizationDetails' => $accessToken->getAuthorizationDetails()],
        );

        if (($accessTokenAuthorizationDetails = $accessToken->getAuthorizationDetails()) === null) {
            return $normalizedAuthorizationDetails;
        }

        /** @psalm-suppress MixedAssignment */
        foreach ($accessTokenAuthorizationDetails as $authorizationDetail) {
            if (
                (isset($authorizationDetail['type'])) &&
                ($authorizationDetail['type']) === 'openid_credential'
            ) {
                /** @psalm-suppress MixedAssignment */
                $credentialConfigurationId = $authorizationDetail['credential_configuration_id'] ?? null;
                if ($credentialConfigurationId !== null) {
                    $authorizationDetail['credential_identifiers'] = [$credentialConfigurationId];
                }
                $normalizedAuthorizationDetails[] = $authorizationDetail;
            }
        }

        $this->loggerService->debug(
            'TokenResponse::prepareAuthorizationDetailsExtraParam. Summarized authorization details: ',
            ['authorizationDetails' => $normalizedAuthorizationDetails],
        );

        return ['authorization_details' => $normalizedAuthorizationDetails];
    }


    /**
     * @param \League\OAuth2\Server\Entities\ScopeEntityInterface[] $scopes
     *
     * @return bool
     */
    private function isOpenIDRequest(array $scopes): bool
    {
        // Verify scope and make sure openid exists.
        foreach ($scopes as $scope) {
            if ('openid' === $scope->getIdentifier()) {
                return true;
            }
        }

        return false;
    }


    /**
     * @param string|null $nonce
     */
    public function setNonce(?string $nonce): void
    {
        $this->nonce = $nonce;
    }


    /**
     * @return string|null
     */
    public function getNonce(): ?string
    {
        return $this->nonce;
    }


    /**
     * @param int|null $authTime
     */
    public function setAuthTime(?int $authTime): void
    {
        $this->authTime = $authTime;
    }


    /**
     * @return int|null
     */
    public function getAuthTime(): ?int
    {
        return $this->authTime;
    }


    public function setAcr(?string $acr): void
    {
        $this->acr = $acr;
    }


    public function getAcr(): ?string
    {
        return $this->acr;
    }


    public function getSessionId(): ?string
    {
        return $this->sessionId;
    }


    public function setSessionId(?string $sessionId): void
    {
        $this->sessionId = $sessionId;
    }
}
