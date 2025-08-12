<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers\Api;

use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Codebooks\ApiScopesEnum;
use SimpleSAML\Module\oidc\Codebooks\ParametersEnum;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Exceptions\OidcException;
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
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\GrantTypesEnum;
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
    ) {
        if (!$this->moduleConfig->getApiEnabled()) {
            throw OidcServerException::forbidden('API capabilities not enabled.');
        }
    }

    /**
     */
    public function preAuthorizedCredentialOffer(Request $request): Response
    {
        $this->authorization->requireTokenForAnyOfScope(
            $request,
            [ApiScopesEnum::VciCredentialOffer, ApiScopesEnum::VciAll, ApiScopesEnum::All],
        );

        // Currently, we need a dedicated client for which the PreAuthZed code will be bound to.
        // TODO mivanci: Remove requirement for dedicated client for (pre-)authorization codes.
        $client = $this->clientEntityFactory->getGenericForVciPreAuthZFlow();
        if ($this->clientRepository->findById($client->getIdentifier()) === null) {
            $this->clientRepository->add($client);
        } else {
            $this->clientRepository->update($client);
        }

        $input = $request->getPayload()->all();
        $userAttributes = $input['user_attributes'] ?? [];

        $selectedCredentialConfigurationId = $input['credential_configuration_id'] ?? null;
        if ($selectedCredentialConfigurationId === null) {
            throw new OidcException('No credential configuration ID provided.');
        }
        $credentialConfigurationIdsSupported = $this->moduleConfig->getCredentialConfigurationIdsSupported();

        if (empty($credentialConfigurationIdsSupported)) {
            throw new OidcException('No credential configuration IDs configured.');
        }
        if (!in_array($selectedCredentialConfigurationId, $credentialConfigurationIdsSupported, true)) {
            throw new OidcException(
                'Credential configuration ID not supported: ' . $selectedCredentialConfigurationId,
            );
        }

        $userId = null;
        try {
            $userId = $this->sspBridge->utils()->attributes()->getExpectedAttribute(
                $userAttributes,
                $this->moduleConfig->getUserIdentifierAttribute(),
            );
        } catch (\Throwable $e) {
            $this->loggerService->warning(
                'Could not extract user identifier from user attributes: ' . $e->getMessage(),
            );
        }

        if ($userId === null) {
            $sortedAttributes = $userAttributes;
            $this->verifiableCredentials->helpers()->arr()->hybridSort($sortedAttributes);
            $userId = 'vci_preauthz_' . hash('sha256', serialize($sortedAttributes));
        }

        $oldUserEntity = $this->userRepository->getUserEntityByIdentifier($userId);

        $userEntity = $this->userEntityFactory->fromData($userId, $userAttributes);

        if ($oldUserEntity instanceof UserEntity) {
            $this->userRepository->update($userEntity);
        } else {
            $this->userRepository->add($userEntity);
        }


        $authCodeId = $this->sspBridge->utils()->random()->generateID();

        if (($authCode = $this->authCodeRepository->findById($authCodeId)) === null) {
            $authCode = $this->authCodeEntityFactory->fromData(
                id: $authCodeId,
                client: $client,
                scopes: [
                    new ScopeEntity('openid'),
                    new ScopeEntity($selectedCredentialConfigurationId),
                ],
                expiryDateTime: new \DateTimeImmutable('+10 minutes'),
                userIdentifier: $userId,
                redirectUri: 'openid-credential-offer://',
            );

            $this->authCodeRepository->persistNewAuthCode($authCode);
        }

        $credentialOffer = $this->verifiableCredentials->credentialOfferFactory()->from(
            parameters: [
                ClaimsEnum::CredentialIssuer->value => $this->moduleConfig->getIssuer(),
                ClaimsEnum::CredentialConfigurationIds->value => [
                    $selectedCredentialConfigurationId,
                ],
                ClaimsEnum::Grants->value => [
                    GrantTypesEnum::PreAuthorizedCode->value => [
                        ClaimsEnum::PreAuthorizedCode->value => $authCode->getIdentifier(),
                        // TODO mivanci support for TxCode
                        //                        ClaimsEnum::TxCode->value => [
                        //                            ClaimsEnum::InputMode->value => 'numeric',
                        //                            ClaimsEnum::Length->value => 6,
                        //                            ClaimsEnum::Description->value => 'Sent to user mail',
                        //                        ],
                    ],
                ],
            ],
        );

        $credentialOfferValue = $credentialOffer->jsonSerialize();
        $parameterName = ParametersEnum::CredentialOfferUri->value;
        if (is_array($credentialOfferValue)) {
            $parameterName = ParametersEnum::CredentialOffer->value;
            $credentialOfferValue = json_encode($credentialOfferValue);
        }

        $credentialOfferUri = "openid-credential-offer://?$parameterName=$credentialOfferValue";

        return $this->routes->newJsonResponse(
            data: [
                'credential_offer_uri' => $credentialOfferUri,
            ],
        );
    }
}
