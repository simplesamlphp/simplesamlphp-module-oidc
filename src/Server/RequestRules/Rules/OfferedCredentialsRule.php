<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\IssuerStateRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;

/**
 * A request following a Credential Offer (one IssuerStateRule accepted an issuer_state for) may ask only for the
 * credential configurations that offer offered: through a scope which is a configuration ID (OpenID4VCI 1.0
 * section 5.1.2), or through authorization_details of type openid_credential (section 5.1.1). What the offer
 * offered is what the issuer authorized; without this, the issuer_state of an offer for one credential would
 * admit a wallet -- a non-registered one included, which can request nothing without an offer -- to any other.
 * Scopes which are not configuration IDs (openid, for example) are not the offer's to decide.
 *
 * A configuration the offer did not offer is refused before the End-User is asked to log in, so this rule runs
 * after ScopeRule and AuthorizationDetailsRule and before PromptRule and MaxAgeRule. The refusal goes to the
 * redirect URI like ScopeRule's: the issuer_state is valid, so the client and its redirect URI were accepted.
 *
 * @extends \SimpleSAML\Module\oidc\Server\RequestRules\Rules\AbstractRule<null>
 */
class OfferedCredentialsRule extends AbstractRule
{
    public function __construct(
        RequestParamsResolver $requestParamsResolver,
        Helpers $helpers,
        protected readonly IssuerStateRepository $issuerStateRepository,
        protected readonly ModuleConfig $moduleConfig,
    ) {
        parent::__construct($requestParamsResolver, $helpers);
    }


    /**
     * @inheritDoc
     *
     * @param \SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface $responseMode
     * @param \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum[] $allowedServerRequestMethods
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \SimpleSAML\OpenID\Exceptions\OpenIdException
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        ResponseModeInterface $responseMode = new QueryResponseMode(),
        array $allowedServerRequestMethods = [HttpMethodsEnum::GET],
    ): ?Result {
        $issuerStateValue = $currentResultBag->get(IssuerStateRule::class)?->getValue();

        if (!is_string($issuerStateValue)) {
            return new Result($this->getKey(), null);
        }

        // IssuerStateRule has just found it redeemable. One gone since offers nothing.
        $offered = $this->issuerStateRepository->find($issuerStateValue)?->getCredentialConfigurationIds() ?? [];

        $redirectUri = $currentResultBag->getOrFail(ClientRedirectUriRule::class)->getValue();
        $state = $currentResultBag->getOrFail(StateRule::class)->getValue();
        $client = $currentResultBag->getOrFail(ClientRule::class)->getValue();
        $logContext = ['client_id' => $client instanceof ClientEntityInterface ? $client->getIdentifier() : null];

        $configurationIds = $this->moduleConfig->getVciCredentialConfigurationIdsSupported();

        $scopes = $currentResultBag->getOrFail(ScopeRule::class)->getValue();
        foreach ($scopes as $scope) {
            $scopeIdentifier = $scope->getIdentifier();

            if (
                in_array($scopeIdentifier, $configurationIds, true) &&
                !in_array($scopeIdentifier, $offered, true)
            ) {
                $loggerService->notice(
                    'Authorization request rejected: `scope` names a credential configuration its Credential ' .
                    'Offer did not offer.',
                    [...$logContext, 'scope' => $scopeIdentifier],
                );
                throw OidcServerException::invalidScope($scopeIdentifier, $redirectUri, $state, $responseMode);
            }
        }

        $authorizationDetails = $currentResultBag->get(AuthorizationDetailsRule::class)?->getValue();
        /** @psalm-suppress MixedAssignment */
        foreach ($authorizationDetails ?? [] as $authorizationDetail) {
            /** @psalm-suppress MixedAssignment */
            $credentialConfigurationId = is_array($authorizationDetail) ?
            ($authorizationDetail[ClaimsEnum::CredentialConfigurationId->value] ?? null) :
            null;

            if (is_string($credentialConfigurationId) && in_array($credentialConfigurationId, $offered, true)) {
                continue;
            }

            $loggerService->notice(
                'Authorization request rejected: `authorization_details` name a credential configuration its ' .
                'Credential Offer did not offer.',
                [
                    ...$logContext,
                    'credential_configuration_id' => is_scalar($credentialConfigurationId) ?
                        (string)$credentialConfigurationId :
                        get_debug_type($credentialConfigurationId),
                ],
            );
            throw OidcServerException::invalidAuthorizationDetails(
                'The Credential Offer did not offer the credential configuration requested.',
                $redirectUri,
                $state,
                $responseMode,
            );
        }

        return new Result($this->getKey(), null);
    }
}
