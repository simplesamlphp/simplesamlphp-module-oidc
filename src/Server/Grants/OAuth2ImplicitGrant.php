<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\Grants;

use DateInterval;
use League\OAuth2\Server\Grant\ImplicitGrant;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest as OAuth2AuthorizationRequest;
use LogicException;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Grants\Interfaces\AuthorizationValidatableWithCheckerResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\RequestRulesManager;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\ClientIdRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\RedirectUriRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\ScopeRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\StateRule;

class OAuth2ImplicitGrant extends ImplicitGrant implements AuthorizationValidatableWithCheckerResultBagInterface
{
    protected DateInterval $accessTokenTTL;

    protected string $queryDelimiter;

    protected RequestRulesManager $requestRulesManager;

    /** @psalm-suppress PropertyNotSetInConstructor */
    protected $revokeRefreshTokens;

    /** @psalm-suppress PropertyNotSetInConstructor */
    protected $defaultScope;

    /** @psalm-suppress PropertyNotSetInConstructor */
    protected $privateKey;

    /** @psalm-suppress PropertyNotSetInConstructor */
    protected $refreshTokenTTL;

    /** @psalm-suppress PropertyNotSetInConstructor */
    protected $userRepository;

    /** @psalm-suppress PropertyNotSetInConstructor */
    protected $refreshTokenRepository;

    /** @psalm-suppress PropertyNotSetInConstructor */
    protected $authCodeRepository;

    /**
     * @psalm-suppress PropertyNotSetInConstructor
     * @var \League\OAuth2\Server\Repositories\ScopeRepositoryInterface
     */
    protected $scopeRepository;

    /** @psalm-suppress PropertyNotSetInConstructor */
    protected $accessTokenRepository;

    /** @psalm-suppress PropertyNotSetInConstructor */
    protected $clientRepository;


    /**
     * @inheritDoc
     */
    public function __construct(
        DateInterval $accessTokenTTL,
        string $queryDelimiter = '#',
        RequestRulesManager $requestRulesManager = null,
    ) {
        parent::__construct($accessTokenTTL, $queryDelimiter);

        if ($requestRulesManager === null) {
            throw new LogicException('Can not validate request (no RequestRulesManager defined)');
        }

        $this->accessTokenTTL = $accessTokenTTL;
        $this->queryDelimiter = $queryDelimiter;
        $this->requestRulesManager = $requestRulesManager;
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Throwable
     */
    public function validateAuthorizationRequestWithCheckerResultBag(
        ServerRequestInterface $request,
        ResultBagInterface $resultBag,
    ): OAuth2AuthorizationRequest {
        $rulesToExecute = [
            ScopeRule::class,
        ];

        // Since we have already validated redirect_uri, and we have state, make it available for other checkers.
        $this->requestRulesManager->predefineResultBag($resultBag);

        /** @var string $redirectUri */
        $redirectUri = $resultBag->getOrFail(RedirectUriRule::class)->getValue();
        /** @var string|null $state */
        $state = $resultBag->getOrFail(StateRule::class)->getValue();
        /** @var \SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface $client */
        $client = $resultBag->getOrFail(ClientIdRule::class)->getValue();

        // Some rules have to have certain things available in order to work properly...
        $this->requestRulesManager->setData('default_scope', $this->defaultScope);
        $this->requestRulesManager->setData('scope_delimiter_string', self::SCOPE_DELIMITER_STRING);

        $resultBag = $this->requestRulesManager->check($request, $rulesToExecute);

        /** @var \League\OAuth2\Server\Entities\ScopeEntityInterface[] $scopes */
        $scopes = $resultBag->getOrFail(ScopeRule::class)->getValue();

        $oAuth2AuthorizationRequest = new OAuth2AuthorizationRequest();

        $oAuth2AuthorizationRequest->setClient($client);
        $oAuth2AuthorizationRequest->setRedirectUri($redirectUri);
        $oAuth2AuthorizationRequest->setScopes($scopes);
        $oAuth2AuthorizationRequest->setGrantTypeId($this->getIdentifier());

        if ($state !== null) {
            $oAuth2AuthorizationRequest->setState($state);
        }

        return $oAuth2AuthorizationRequest;
    }
}
