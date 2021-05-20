<?php

namespace SimpleSAML\Modules\OpenIDConnect\Server\Grants;

use DateInterval;
use League\OAuth2\Server\Grant\ImplicitGrant;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest as OAuth2AuthorizationRequest;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Modules\OpenIDConnect\Entity\Interfaces\ClientEntityInterface;
use SimpleSAML\Modules\OpenIDConnect\Server\Grants\Interfaces\AuthorizationValidatableWithClientAndRedirectUriInterface;
use SimpleSAML\Modules\OpenIDConnect\Server\Grants\Traits\ScopesValidationTrait;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\RequestRulesManager;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Result;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules\RedirectUriRule;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules\ScopeRule;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules\StateRule;

class OAuth2ImplicitGrant extends ImplicitGrant implements AuthorizationValidatableWithClientAndRedirectUriInterface
{
    use ScopesValidationTrait;

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

        $this->requestRulesManager = $requestRulesManager;
    }

    public function validateAuthorizationRequestWithClientAndRedirectUri(
        ServerRequestInterface $request,
        ClientEntityInterface $client,
        string $redirectUri,
        string $state = null
    ): OAuth2AuthorizationRequest {
        $rulesToExecute = [
            ScopeRule::getKey(),
        ];

        // Since we have already validated redirect_uri and we have state, make it available for other checkers.
        $this->requestRulesManager->predefineResult(new Result(RedirectUriRule::getKey(), $redirectUri));
        $this->requestRulesManager->predefineResult(new Result(StateRule::getKey(), $state));

        // Some rules have to have certain things available in order to work properly...
        $this->requestRulesManager->setData('default_scope', $this->defaultScope);
        $this->requestRulesManager->setData('scope_delimiter_string', self::SCOPE_DELIMITER_STRING);

        $resultBag = $this->requestRulesManager->check($request, $rulesToExecute);

        /** @var array $scopes */
        $scopes = $resultBag->getOrFail(ScopeRule::getKey())->getValue();

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
