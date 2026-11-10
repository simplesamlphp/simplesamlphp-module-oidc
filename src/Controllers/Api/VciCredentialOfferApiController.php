<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers\Api;

use RuntimeException;
use SimpleSAML\Error\ConfigurationError;
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
use Throwable;

class VciCredentialOfferApiController
{
    final public const string HEADER_WWW_AUTHENTICATE = 'WWW-Authenticate';


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
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

        if (!$this->moduleConfig->getVciEnabled()) {
            $this->loggerService->warning('Verifiable Credential capabilities not enabled.');
            throw OidcServerException::forbidden('Verifiable Credential capabilities not enabled.');
        }
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function credentialOffer(Request $request): Response
    {
        if (!$this->moduleConfig->getApiVciCredentialOfferEndpointEnabled()) {
            $this->loggerService->warning('Credential Offer API endpoint not enabled.');
            throw OidcServerException::forbidden('Credential Offer API endpoint not enabled.');
        }

        $this->loggerService->debug('VciCredentialOfferApiController::credentialOffer');

        $this->loggerService->debug('VciCredentialOfferApiController: Processing credential-offer request.');

        try {
            $credentialConfigurationLimit = $this->authorization->requireTokenForAnyOfScope(
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
        } catch (ConfigurationError $e) {
            // The token's credential configurations are malformed. That is this server's configuration, not
            // the caller's request, and the caller is answered in JSON as everywhere else in this API.
            $this->loggerService->error(
                'VciCredentialOfferApiController: API token configuration could not be read: ' . $e->getMessage(),
            );
            return $this->routes->newJsonErrorResponse(
                error: 'server_error',
                description: 'Authorization could not be resolved.',
                httpCode: Response::HTTP_INTERNAL_SERVER_ERROR,
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

        $credentialConfiguration = $this->moduleConfig->getVciCredentialConfiguration($credentialConfigurationId);

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

        // Checked after the configuration is known to exist, so an unknown one is answered as unknown whatever the
        // token's list says. Telling the caller that a configuration exists costs nothing: the Credential Issuer
        // metadata publishes every one. Both grants are held to the list: an authorization code offer carries no
        // attributes, but which credentials a token may advertise to wallets is still the token's limit.
        if (!$credentialConfigurationLimit->allows($credentialConfigurationId)) {
            $this->loggerService->warning(
                'VciCredentialOfferApiController: The API token may not offer this credential configuration.',
                ['credentialConfigurationId' => $credentialConfigurationId],
            );
            return $this->routes->newJsonErrorResponse(
                error: 'insufficient_scope',
                description: 'The API token may not offer this credential configuration.',
                httpCode: Response::HTTP_FORBIDDEN,
                headers: [self::HEADER_WWW_AUTHENTICATE => 'Bearer error="insufficient_scope"'],
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

        // Building an offer stores what it grants and may mail a transaction code. A failure there is this
        // server's (storage, mail delivery), and is answered as one in JSON, as every other answer of this API
        // is, rather than left to reach SimpleSAMLphp's HTML error page.
        try {
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
                    'VciCredentialOfferApiController: Pre-authorized credential-offer request accepted.',
                    [
                        'useTxCode' => $useTxCode,
                        'authenticationSourceId' => $authenticationSourceId,
                        'usersEmailAttributeName' => $usersEmailAttributeName,
                    ],
                );

                // The transaction code goes to the user's email address, so attributes holding none are the
                // caller's mistake, answered as one before anything is stored.
                if ($useTxCode) {
                    try {
                        $this->credentialOfferUriFactory->getUserEmail(
                            $usersEmailAttributeName ?? $this->moduleConfig->getDefaultUsersEmailAttributeName(),
                            $userAttributes,
                        );
                    } catch (RuntimeException $exception) {
                        $this->loggerService->notice(
                            'VciCredentialOfferApiController: No email address for the transaction code: ' .
                            $exception->getMessage(),
                        );
                        return $this->routes->newJsonErrorResponse(
                            error: 'invalid_request',
                            description: 'User attributes hold no email address to send the transaction code to.',
                            httpCode: Response::HTTP_BAD_REQUEST,
                        );
                    }
                }

                $credentialOfferUri = $this->credentialOfferUriFactory->buildPreAuthorized(
                    [$credentialConfigurationId],
                    $userAttributes,
                    $useTxCode,
                    $usersEmailAttributeName,
                );
            }
        } catch (Throwable $exception) {
            $this->loggerService->error(
                'VciCredentialOfferApiController: Credential Offer could not be built: ' . $exception->getMessage(),
                ['grantType' => $grantType],
            );
            return $this->routes->newJsonErrorResponse(
                error: 'server_error',
                description: 'Credential Offer could not be built.',
                httpCode: Response::HTTP_INTERNAL_SERVER_ERROR,
            );
        }

        if ($credentialOfferUri !== null) {
            $data = [
                'credential_offer_uri' => $credentialOfferUri,
            ];

            $this->loggerService->debug(
                'VciCredentialOfferApiController: Credential Offer URI built successfully.',
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
