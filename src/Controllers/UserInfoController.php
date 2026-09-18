<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers;

use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Error\UserNotFound;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Controllers\Traits\RequestTrait;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\ResourceServer;
use SimpleSAML\Module\oidc\Services\ErrorResponder;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class UserInfoController
{
    use RequestTrait;


    public function __construct(
        private readonly ResourceServer $resourceServer,
        private readonly AccessTokenRepository $accessTokenRepository,
        private readonly UserRepository $userRepository,
        private readonly AllowedOriginRepository $allowedOriginRepository,
        private readonly ClaimTranslatorExtractor $claimTranslatorExtractor,
        private readonly PsrHttpBridge $psrHttpBridge,
        private readonly ErrorResponder $errorResponder,
        private readonly Routes $routes,
    ) {
    }


    /**
     * @throws \SimpleSAML\Error\UserNotFound
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    public function __invoke(ServerRequestInterface $request): Response
    {
        // Check if this is actually a CORS preflight request...
        if (strtoupper($request->getMethod()) === 'OPTIONS') {
            return $this->psrHttpBridge->getHttpFoundationFactory()->createResponse($this->handleCors($request));
        }

        $authorization = $this->resourceServer->validateAuthenticatedRequest($request);

        /** @var string $tokenId */
        $tokenId = $authorization->getAttribute('oauth_access_token_id');
        /** @var string[] $scopes */
        $scopes = $authorization->getAttribute('oauth_scopes');

        $accessToken = $this->accessTokenRepository->findById($tokenId);
        if (!$accessToken instanceof AccessTokenEntity) {
            throw new UserNotFound('Access token not found');
        }
        $user = $this->getUser($accessToken);

        // The claims are read from the user record as it is now; the response is the fresher statement when an
        // attribute has changed since the token was minted.
        $claims = $this->claimTranslatorExtractor->extract($scopes, $user->getClaims());
        $requestedClaims =  $accessToken->getRequestedClaims();
        $additionalClaims = $this->claimTranslatorExtractor->extractAdditionalUserInfoClaims(
            $requestedClaims,
            $user->getClaims(),
        );
        $claims = array_merge($additionalClaims, $claims);

        // The subject is the exception: it is the one the presented access token carries, resolved once when the
        // token was minted and shared with the ID token issued alongside, so this response can not name the
        // End-User differently from that ID token (OpenID Connect Core 1.0 section 5.3.2 has the client reject
        // it), and it is present even when the 'sub' translation yields nothing ("The sub (subject) Claim MUST
        // always be returned in the UserInfo Response"). Written last so that nothing above overrides it. A token
        // minted before the module wrote a 'typ' header carries the internal user identifier as its 'sub', not
        // the resolved subject; for such a token the 'sub' the 'openid' scope released above stands, as it did
        // when its ID token was issued.
        if ($authorization->getAttribute('oauth_access_token_typ') !== null) {
            /** @psalm-suppress MixedAssignment */
            $subject = $authorization->getAttribute('oauth_user_id');
            if (is_string($subject) && $subject !== '') {
                $claims[ClaimsEnum::Sub->value] = $subject;
            }
        }

        return $this->routes->newJsonResponse($claims);
    }


    public function userInfo(Request $request): Response
    {
        try {
            $response = $this->__invoke($this->psrHttpBridge->getPsrHttpFactory()->createRequest($request));

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
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \SimpleSAML\Error\UserNotFound
     */
    private function getUser(AccessTokenEntity $accessToken): UserEntity
    {
        $userIdentifier = (string) $accessToken->getUserIdentifier();
        $user = $this->userRepository->getUserEntityByIdentifier($userIdentifier);
        if (!$user instanceof UserEntity) {
            throw new UserNotFound("User $userIdentifier not found");
        }

        return $user;
    }
}
