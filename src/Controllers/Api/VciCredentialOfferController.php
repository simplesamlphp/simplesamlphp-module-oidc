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
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class VciCredentialOfferController
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
            throw OidcServerException::forbidden('API capabilities not enabled.');
        }
    }

    /**
     */
    public function credentialOffer(Request $request): Response
    {
        $this->loggerService->debug('VCI credential offer request data: ', $request->getPayload()->all());
        try {
            $this->authorization->requireTokenForAnyOfScope(
                $request,
                [ApiScopesEnum::VciCredentialOffer, ApiScopesEnum::VciAll, ApiScopesEnum::All],
            );
        } catch (AuthorizationException $e) {
            return $this->routes->newJsonErrorResponse(
                error: 'unauthorized',
                description: $e->getMessage(),
                httpCode: Response::HTTP_UNAUTHORIZED,
            );
        }

        $input = $request->getPayload()->all();
        /** @psalm-suppress MixedAssignment */
        $userAttributes = $input['user_attributes'] ?? [];
        $userAttributes = is_array($userAttributes) ? $userAttributes : [];

        $selectedCredentialConfigurationId = $input['credential_configuration_id'] ?? null;

        if (!is_string($selectedCredentialConfigurationId)) {
            return $this->routes->newJsonErrorResponse(
                error: 'invalid_request',
                description: 'No credential configuration ID provided.',
                httpCode: Response::HTTP_BAD_REQUEST,
            );
        }

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

        $credentialOfferUri = $this->credentialOfferUriFactory->buildPreAuthorized(
            [$selectedCredentialConfigurationId],
            $userAttributes,
            $useTxCode,
            $usersEmailAttributeName,
        );

        return $this->routes->newJsonResponse(
            data: [
                'credential_offer_uri' => $credentialOfferUri,
            ],
        );
    }
}
