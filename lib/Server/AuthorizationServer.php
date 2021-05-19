<?php

namespace SimpleSAML\Modules\OpenIDConnect\Server;

use League\OAuth2\Server\AuthorizationServer as OAuth2AuthorizationServer;
use SimpleSAML\Error\BadRequest;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest as OAuth2AuthorizationRequest;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Error\Exception;
use SimpleSAML\Modules\OpenIDConnect\Server\Exceptions\OidcServerException;
use SimpleSAML\Modules\OpenIDConnect\Server\Grants\Interfaces\AuthorizationValidatableWithClientAndRedirectUriInterface;
use SimpleSAML\Modules\OpenIDConnect\Server\Grants\Traits\ClientRedirectUriValidationTrait;

class AuthorizationServer extends OAuth2AuthorizationServer
{
    use ClientRedirectUriValidationTrait;

    /**
     * @var ClientRepositoryInterface
     */
    protected $clientRepository;

    /**
     * @inheritDoc
     */
    public function __construct(
        ClientRepositoryInterface $clientRepository,
        AccessTokenRepositoryInterface $accessTokenRepository,
        ScopeRepositoryInterface $scopeRepository,
        $privateKey,
        $encryptionKey,
        ResponseTypeInterface $responseType = null
    ) {
        parent::__construct(
            $clientRepository,
            $accessTokenRepository,
            $scopeRepository,
            $privateKey,
            $encryptionKey,
            $responseType
        );

        $this->clientRepository = $clientRepository;
    }

    /**
     * @inheritDoc
     */
    public function validateAuthorizationRequest(ServerRequestInterface $request): OAuth2AuthorizationRequest
    {
        // state and redirectUri is used here so we can return HTTP redirect error in case of invalid response_type.
        /** @var string|null $state */
        $state = $request->getQueryParams()['state'] ?? null;

        try {
            $client = $this->getClientOrFail($request);
            $redirectUri = $this->getRedirectUriOrFail($client, $request);
        } catch (OidcServerException $exception) {
            $reason = \sprintf("%s %s", $exception->getMessage(), $exception->getHint() ?? '');
            throw new BadRequest($reason);
        }

        foreach ($this->enabledGrantTypes as $grantType) {
            if ($grantType->canRespondToAuthorizationRequest($request)) {
                if (! $grantType instanceof AuthorizationValidatableWithClientAndRedirectUriInterface) {
                    throw OidcServerException::serverError('Grant type must be validatable with already validated ' .
                                                           'client and redirect_uri');
                }

                return $grantType->validateAuthorizationRequestWithClientAndRedirectUri(
                    $request,
                    $client,
                    $redirectUri,
                    $state
                );
            }
        }

        throw OidcServerException::unsupportedResponseType($redirectUri, $state);
    }
}
