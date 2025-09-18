<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers\Api;

use SimpleSAML\Module\oidc\Codebooks\ApiScopesEnum;
use SimpleSAML\Module\oidc\Exceptions\AuthorizationException;
use SimpleSAML\Module\oidc\Factories\CredentialOfferUriFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\Api\Authorization;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\Codebooks\GrantTypesEnum;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * TODO mivanci Add API documentation.
 */
class VciCredentialOfferApiController
{
    /**
     * @throws OidcServerException
     */
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly Authorization $authorization,
        protected readonly LoggerService $loggerService,
        protected readonly Routes $routes,
        protected readonly CredentialOfferUriFactory $credentialOfferUriFactory,
    ) {
        if (!$this->moduleConfig->getApiEnabled()) {
            $this->loggerService->warning('API capabilities not enabled.');
            throw OidcServerException::forbidden('API capabilities not enabled.');
        }

        if (!$this->moduleConfig->getVerifiableCredentialEnabled()) {
            $this->loggerService->warning('Verifiable Credential capabilities not enabled.');
            throw OidcServerException::forbidden('Verifiable Credential capabilities not enabled.');
        }
    }

    /**
     */
    public function credentialOffer(Request $request): Response
    {
        $this->loggerService->debug('VciCredentialOfferApiController::credentialOffer');

        $this->loggerService->debug(
            'VciCredentialOfferApiController: Request data: ',
            $request->getPayload()->all(),
        );

        try {
            $this->authorization->requireTokenForAnyOfScope(
                $request,
                [ApiScopesEnum::VciCredentialOffer, ApiScopesEnum::VciAll, ApiScopesEnum::All],
            );
        } catch (AuthorizationException $e) {
            $this->loggerService->error(
                'VciCredentialOfferApiController: AuthorizationException: ' . $e->getMessage(),
            );
            return $this->routes->newJsonErrorResponse(
                error: 'unauthorized',
                description: $e->getMessage(),
                httpCode: Response::HTTP_UNAUTHORIZED,
            );
        }

        $input = $request->getPayload()->all();

        $credentialConfigurationId = $input['credential_configuration_id'] ?? null;

        if (!is_string($credentialConfigurationId)) {
            $this->loggerService->error(
                'VciCredentialOfferApiController: credential_configuration_id not provided or not a string.',
            );
            return $this->routes->newJsonErrorResponse(
                error: 'invalid_request',
                description: 'No credential configuration ID (credential_configuration_id) provided.',
                httpCode: Response::HTTP_BAD_REQUEST,
            );
        }

        $credentialConfiguration = $this->moduleConfig->getCredentialConfiguration($credentialConfigurationId);

        if (!is_array($credentialConfiguration)) {
            $this->loggerService->error(
                'VciCredentialOfferApiController: Provided Credential Configuration ID is not supported.',
                ['credentialConfigurationId' => $credentialConfigurationId],
            );
            return $this->routes->newJsonErrorResponse(
                error: 'invalid_request',
                description: 'Provided credential configuration ID (credential_configuration_id) is not supported.',
                httpCode: Response::HTTP_BAD_REQUEST,
            );
        }

        $grantType = $input['grant_type'] ?? null;

        if (!is_string($grantType)) {
            $this->loggerService->error('VciCredentialOfferApiController: Grant Type (grant_type) not provided.');
            return $this->routes->newJsonErrorResponse(
                error: 'invalid_request',
                description: 'No credential Grant Type (grant_type) provided.',
                httpCode: Response::HTTP_BAD_REQUEST,
            );
        }

        $grantTypeEnum = GrantTypesEnum::tryFrom($grantType);

        if (!$grantTypeEnum instanceof GrantTypesEnum) {
            $this->loggerService->error(
                'VciCredentialOfferApiController: Invalid credential Grant Type (grant_type) provided.',
                ['grantType' => $grantType],
            );
            return $this->routes->newJsonErrorResponse(
                error: 'invalid_request',
                description: 'Invalid credential Grant Type (grant_type) provided.',
                httpCode: Response::HTTP_BAD_REQUEST,
            );
        }

        if (!$grantTypeEnum->canBeUsedForVerifiableCredentialIssuance()) {
            $this->loggerService->error(
                'VciCredentialOfferApiController: Provided Grant Type can not be used for verifiable credential' .
                ' issuance.',
                ['grantType' => $grantType],
            );
            return $this->routes->newJsonErrorResponse(
                error: 'invalid_request',
                description: 'Provided Grant Type can not be used for verifiable credential issuance.',
                httpCode: Response::HTTP_BAD_REQUEST,
            );
        }

        $credentialOfferUri = null;

        if ($grantTypeEnum === GrantTypesEnum::AuthorizationCode) {
            $this->loggerService->debug(
                'VciCredentialOfferApiController: AuthorizationCode Grant Type provided. Building credential ' .
                'offer for Authorization Code Flow.',
            );
            $credentialOfferUri = $this->credentialOfferUriFactory->buildForAuthorization(
                [$credentialConfigurationId],
            );
        }

        if ($grantTypeEnum === GrantTypesEnum::PreAuthorizedCode) {
            $this->loggerService->debug(
                'VciCredentialOfferApiController: PreAuthorizedCode Grant Type provided. Building credential ' .
                'offer for Pre-authorized Code Flow.',
            );

            /** @psalm-suppress MixedAssignment */
            $userAttributes = $input['user_attributes'] ?? [];
            $userAttributes = is_array($userAttributes) ? $userAttributes : [];
            $useTxCode = boolval($input['use_tx_code'] ?? false);
            /** @psalm-suppress MixedAssignment */
            $usersEmailAttributeName = $input['users_email_attribute_name'] ?? null;
            $usersEmailAttributeName = is_string($usersEmailAttributeName) ? $usersEmailAttributeName : null;
            /** @psalm-suppress MixedAssignment */
            $authenticationSourceId = $input['authentication_source_id'] ?? null;
            $authenticationSourceId = is_string($authenticationSourceId) ? $authenticationSourceId : null;

            if (is_null($usersEmailAttributeName) && is_string($authenticationSourceId)) {
                $usersEmailAttributeName = $this->moduleConfig->getUsersEmailAttributeNameForAuthSourceId(
                    $authenticationSourceId,
                );
            }

            $this->loggerService->debug(
                'VciCredentialOfferApiController: PreAuthorizedCode data:',
                [
                    'userAttributes' => $userAttributes,
                    'useTxCode' => $useTxCode,
                    'authenticationSourceId' => $authenticationSourceId,
                    'usersEmailAttributeName' => $usersEmailAttributeName,
                ],
            );

            $credentialOfferUri = $this->credentialOfferUriFactory->buildPreAuthorized(
                [$credentialConfigurationId],
                $userAttributes,
                $useTxCode,
                $usersEmailAttributeName,
            );
        }

        if ($credentialOfferUri !== null) {
            $data = [
                'credential_offer_uri' => $credentialOfferUri,
            ];

            $this->loggerService->debug(
                'VciCredentialOfferApiController: Credential Offer URI built successfully, returning data:',
                $data,
            );
            return $this->routes->newJsonResponse(
                data: $data,
            );
        }

        $this->loggerService->debug(
            'VciCredentialOfferApiController: Credential Offer URI NOT built for provided Grant Type.',
            ['grantType' => $grantType],
        );

        return $this->routes->newJsonErrorResponse(
            error: 'invalid_request',
            description: 'No implementation for provided Grant Type.',
            httpCode: Response::HTTP_BAD_REQUEST,
        );
    }
}
