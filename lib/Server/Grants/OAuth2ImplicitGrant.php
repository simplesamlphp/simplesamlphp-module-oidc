<?php

namespace SimpleSAML\Module\oidc\Server\Grants;

use DateInterval;
use League\OAuth2\Server\Grant\ImplicitGrant;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest as OAuth2AuthorizationRequest;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entity\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Server\Grants\Interfaces\AuthorizationValidatableWithClientAndRedirectUriInterface;
use SimpleSAML\Module\oidc\Utils\Checker\RequestRulesManager;
use SimpleSAML\Module\oidc\Utils\Checker\Result;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\RedirectUriRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\ScopeRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\StateRule;

class OAuth2ImplicitGrant extends ImplicitGrant implements AuthorizationValidatableWithClientAndRedirectUriInterface
{
    /**
     * @var DateInterval
     */
    protected $accessTokenTTL;
    /**
     * @var string
     */
    protected $queryDelimiter;
    /**
     * @var RequestRulesManager
     */
    protected $requestRulesManager;

    /**
     * @inheritDoc
     */
    public function __construct(
        DateInterval $accessTokenTTL,
        $queryDelimiter = '#',
        RequestRulesManager $requestRulesManager = null
    ) {
        parent::__construct($accessTokenTTL, $queryDelimiter);

        if ($requestRulesManager === null) {
            throw new \LogicException('Can not validate request (no RequestRulesManager defined)');
        }

        $this->accessTokenTTL = $accessTokenTTL;
        $this->queryDelimiter = $queryDelimiter;
        $this->requestRulesManager = $requestRulesManager;
    }

    public function validateAuthorizationRequestWithClientAndRedirectUri(
        ServerRequestInterface $request,
        ClientEntityInterface $client,
        string $redirectUri,
        string $state = null
    ): OAuth2AuthorizationRequest {
        $rulesToExecute = [
            ScopeRule::class,
        ];

        // Since we have already validated redirect_uri and we have state, make it available for other checkers.
        $this->requestRulesManager->predefineResult(new Result(RedirectUriRule::class, $redirectUri));
        $this->requestRulesManager->predefineResult(new Result(StateRule::class, $state));

        // Some rules have to have certain things available in order to work properly...
        $this->requestRulesManager->setData('default_scope', $this->defaultScope);
        $this->requestRulesManager->setData('scope_delimiter_string', self::SCOPE_DELIMITER_STRING);

        $resultBag = $this->requestRulesManager->check($request, $rulesToExecute);

        /** @var array $scopes */
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
