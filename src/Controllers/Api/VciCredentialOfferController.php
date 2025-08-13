<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers\Api;

use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Codebooks\ApiScopesEnum;
use SimpleSAML\Module\oidc\Exceptions\AuthorizationException;
use SimpleSAML\Module\oidc\Factories\CredentialOfferUriFactory;
use SimpleSAML\Module\oidc\Factories\Entities\AuthCodeEntityFactory;
use SimpleSAML\Module\oidc\Factories\Entities\ClientEntityFactory;
use SimpleSAML\Module\oidc\Factories\Entities\UserEntityFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AuthCodeRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\Api\Authorization;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\VerifiableCredentials;
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
        protected readonly VerifiableCredentials $verifiableCredentials,
        protected readonly ClientEntityFactory $clientEntityFactory,
        protected readonly ClientRepository $clientRepository,
        protected readonly SspBridge $sspBridge,
        protected readonly LoggerService $loggerService,
        protected readonly UserRepository $userRepository,
        protected readonly UserEntityFactory $userEntityFactory,
        protected readonly AuthCodeRepository $authCodeRepository,
        protected readonly AuthCodeEntityFactory $authCodeEntityFactory,
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
        $userAttributes = $input['user_attributes'] ?? [];

        $selectedCredentialConfigurationId = $input['credential_configuration_id'] ?? null;

        if (!is_string($selectedCredentialConfigurationId)) {
            return $this->routes->newJsonErrorResponse(
                error: 'invalid_request',
                description: 'No credential configuration ID provided.',
                httpCode: Response::HTTP_BAD_REQUEST,
            );
        }

        $credentialOfferUri = $this->credentialOfferUriFactory->buildPreAuthorized(
            [$selectedCredentialConfigurationId],
            $userAttributes,
        );

        return $this->routes->newJsonResponse(
            data: [
                'credential_offer_uri' => $credentialOfferUri,
            ],
        );
    }
}
